import { type AttestationVerificationResult } from "@peculiar/attestation-common";
import * as x509 from "@peculiar/x509";
import { BufferSourceConverter, Convert } from "pvtsutils";
import { type MarvellAttestation } from "./attestation";
import { MarvellAttestationParser } from "./parser";
import { MANUFACTURER_ROOT_CERT, OWNER_ROOT_CERT } from "./certs";
import { certificateId, prepareCertificates } from "./certificates";

/** Explicit roles for the two independent authorities required by the Google Cloud HSM profile. */
export interface GoogleCloudHsmTrust {
  manufacturerRoot: x509.X509Certificate;
  ownerRoot: x509.X509Certificate;
}

interface GoogleCloudHsmValidatorParams {
  crypto?: Crypto;
  trustedCerts?: GoogleCloudHsmTrust;
}

interface CertificateNode {
  certificate: x509.X509Certificate;
  id: string;
}

interface NormalizedKey {
  id: string;
  key: CryptoKey;
}

function isCertificate(value: unknown): value is x509.X509Certificate {
  if (!value || typeof value !== "object") return false;
  const cert = value as Partial<x509.X509Certificate>;
  return BufferSourceConverter.isBufferSource(cert.rawData) && typeof cert.verify === "function" && typeof cert.getExtension === "function";
}

function copyTrust(value: unknown): GoogleCloudHsmTrust {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Google Cloud HSM trustedCerts must name manufacturerRoot and ownerRoot.");
  }
  const { manufacturerRoot, ownerRoot } = value as Partial<GoogleCloudHsmTrust>;
  if (!isCertificate(manufacturerRoot) || !isCertificate(ownerRoot)) {
    throw new TypeError("Google Cloud HSM requires both manufacturerRoot and ownerRoot certificates.");
  }
  prepareCertificates([], [manufacturerRoot, ownerRoot]);
  if (BufferSourceConverter.isEqual(manufacturerRoot.publicKey.rawData, ownerRoot.publicKey.rawData)) {
    throw new TypeError("Google Cloud HSM requires independent manufacturer and owner trust keys.");
  }
  return { manufacturerRoot, ownerRoot };
}

/** Signature-only validation of Google's fixed four-certificate layout, not a general path builder. */
export class GoogleCloudHsmAttestationValidator {
  private readonly crypto: Crypto;
  private readonly trust: GoogleCloudHsmTrust;

  constructor(params: GoogleCloudHsmValidatorParams = {}) {
    this.crypto = params.crypto ?? crypto;
    this.trust = copyTrust(params.trustedCerts === undefined ? { manufacturerRoot: MANUFACTURER_ROOT_CERT, ownerRoot: OWNER_ROOT_CERT } : params.trustedCerts);
  }

  /* eslint-disable no-await-in-loop -- Deterministic candidate selection and per-call caches bound the fixed relation search. */
  public async validate(data: Uint8Array | MarvellAttestation, certs: x509.X509Certificate[]): Promise<AttestationVerificationResult> {
    try {
      const { manufacturerRoot, ownerRoot } = this.trust;
      const rootIds = new Set([certificateId(manufacturerRoot), certificateId(ownerRoot)]);
      const nodes = prepareCertificates(certs, [manufacturerRoot, ownerRoot])
        .filter((cert) => !rootIds.has(certificateId(cert)))
        .map((certificate) => ({ certificate, id: certificateId(certificate) }));
      const attestation = BufferSourceConverter.isBufferSource(data) ? new MarvellAttestationParser().parse(data as BufferSource) : (data as MarvellAttestation);
      const normalized = new Map<string, NormalizedKey | null>();
      const keyOf = async (node: CertificateNode): Promise<NormalizedKey | null> => {
        if (normalized.has(node.id)) return normalized.get(node.id)!;
        let result: NormalizedKey | null = null;
        try {
          const publicKey = node.certificate.publicKey;
          // Do not erase RSA-PSS restrictions: PublicKey.export() can otherwise convert a PSS SPKI to PKCS#1.
          if (publicKey.algorithm.name === "RSASSA-PKCS1-v1_5" || publicKey.algorithm.name === "ECDSA") {
            const key = await publicKey.export({ ...publicKey.algorithm, hash: "SHA-256" }, ["verify"], this.crypto);
            const spki = await this.crypto.subtle.exportKey("spki", key);
            result = { id: Convert.ToHex(spki), key };
          }
        } catch {
          // Unsupported or malformed keys in unused candidates do not invalidate a complete proof.
        }
        normalized.set(node.id, result);
        return result;
      };
      const manufacturerKey = await keyOf({ certificate: manufacturerRoot, id: certificateId(manufacturerRoot) });
      const ownerKey = await keyOf({ certificate: ownerRoot, id: certificateId(ownerRoot) });
      if (!manufacturerKey || !ownerKey) throw new Error("Unsupported Google Cloud HSM trust-anchor key.");
      if (manufacturerKey.id === ownerKey.id) throw new Error("Google Cloud HSM requires independent manufacturer and owner trust keys.");

      const edges = new Map<string, boolean>();
      const issuedBy = async (child: CertificateNode, issuer: CertificateNode): Promise<boolean> => {
        const id = `${child.id}:${issuer.id}`;
        if (edges.has(id)) return edges.get(id)!;
        let ok = false;
        try {
          if (child.id !== issuer.id && child.certificate.issuer === issuer.certificate.subject) {
            ok = await child.certificate.verify({ publicKey: issuer.certificate.publicKey, signatureOnly: true }, this.crypto);
          }
        } catch {
          // Reject the connection, not every other candidate in the bundle.
        }
        edges.set(id, ok);
        return ok;
      };
      const manufacturer = { certificate: manufacturerRoot, id: certificateId(manufacturerRoot) };
      const owner = { certificate: ownerRoot, id: certificateId(ownerRoot) };
      const ownerCertificates = new Map<string, CertificateNode[]>();
      const cards: CertificateNode[] = [];
      for (const node of nodes) {
        if (await issuedBy(node, owner)) {
          const key = await keyOf(node);
          if (key) {
            const group = ownerCertificates.get(key.id);
            if (group) group.push(node);
            else ownerCertificates.set(key.id, [node]);
          }
        }
        if (await issuedBy(node, manufacturer)) cards.push(node);
      }

      const signatures = new Map<string, boolean>();
      let relationshipsFound = false;
      for (const card of cards) {
        const cardKey = await keyOf(card);
        const ownerCards = cardKey && ownerCertificates.get(cardKey.id);
        if (!ownerCards) continue;
        for (const partition of nodes) {
          if (!(await issuedBy(partition, card))) continue;
          const partitionKey = await keyOf(partition);
          const ownerPartitions = partitionKey && ownerCertificates.get(partitionKey.id);
          if (!partitionKey || !ownerPartitions || !distinctOwners(card, partition, ownerCards, ownerPartitions)) continue;
          relationshipsFound = true;
          let signature = signatures.get(partitionKey.id);
          if (signature === undefined) {
            signature = false;
            try {
              if (partitionKey.key.algorithm.name === "RSASSA-PKCS1-v1_5") {
                signature = await this.crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, partitionKey.key, attestation.signature as BufferSource, attestation.signedData as BufferSource);
              }
            } catch {
              // Other partition candidates may use a supported signing key.
            }
            signatures.set(partitionKey.id, signature);
          }
          if (signature) return { status: true, signer: partition.certificate, chain: [manufacturerRoot, card.certificate, partition.certificate] };
        }
      }
      return { status: false, error: new Error(relationshipsFound ? "Failed to verify the attestation signature." : "Failed to verify Google Cloud HSM card/partition certificate relationships.") };
    } catch (error) {
      return { status: false, error: error instanceof Error ? error : new Error(String(error)) };
    }
  }
  /* eslint-enable no-await-in-loop */
}

function distinctOwners(card: CertificateNode, partition: CertificateNode, cards: CertificateNode[], partitions: CertificateNode[]): boolean {
  const unused = (node: CertificateNode) => node.id !== card.id && node.id !== partition.id;
  // Only three identities can conflict (the two manufacturer roles and the other owner role).
  // Four distinct candidates per group suffice, keeping selection constant-time per card/partition pair.
  for (const candidate of cards.slice(0, 4)) {
    if (unused(candidate) && partitions.slice(0, 4).some((node) => unused(node) && node.id !== candidate.id)) return true;
  }
  return false;
}
