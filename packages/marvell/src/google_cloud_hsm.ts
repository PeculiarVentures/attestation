import type * as x509 from "@peculiar/x509";
import { BufferSourceConverter, Convert } from "pvtsutils";
import type { MarvellAttestation } from "./attestation";
import { MarvellAttestationParser } from "./parser";
import { MANUFACTURER_ROOT_CERT, OWNER_ROOT_CERT } from "./certs";
import { CertificateLimitError, certificateId, prepareCertificates } from "./certificates";
import {
  type MarvellAttestationVerificationResult,
  type MarvellVerificationCheck,
  type VerificationCandidate,
  asError,
  assertEvidence,
  rejected,
  unchecked,
  uncheckable,
  unverified,
  verificationFailure,
  verified,
} from "./verification";

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

  /* eslint-disable no-await-in-loop -- Per-call caches bound the deterministic candidate and fixed relation searches. */
  public async validate(data: Uint8Array | MarvellAttestation, certs: x509.X509Certificate[]): Promise<MarvellAttestationVerificationResult> {
    let stage: "verification-error" | "malformed-evidence" = "verification-error";
    try {
      const { manufacturerRoot, ownerRoot } = this.trust;
      const rootIds = new Set([certificateId(manufacturerRoot), certificateId(ownerRoot)]);
      const nodes = prepareCertificates(certs, [manufacturerRoot, ownerRoot])
        .filter((cert) => !rootIds.has(certificateId(cert)))
        .map((certificate) => ({ certificate, id: certificateId(certificate) }));
      stage = "malformed-evidence";
      const attestation = BufferSourceConverter.isBufferSource(data) ? new MarvellAttestationParser().parse(data as BufferSource) : (data as MarvellAttestation);
      assertEvidence(attestation);
      stage = "verification-error";
      const normalized = new Map<string, NormalizedKey | null>();
      const keyErrors = new Map<string, MarvellVerificationCheck>();
      let normalizationError: Error | undefined;
      const keyOf = async (node: CertificateNode): Promise<NormalizedKey | null> => {
        if (normalized.has(node.id)) return normalized.get(node.id)!;
        let result: NormalizedKey | null = null;
        let compatibleAlgorithm = false;
        try {
          const publicKey = node.certificate.publicKey;
          // Preserve the Google profile's RSA-PSS restrictions during normalization.
          compatibleAlgorithm = publicKey.algorithm.name === "RSASSA-PKCS1-v1_5" || publicKey.algorithm.name === "ECDSA";
          if (compatibleAlgorithm) {
            const key = await publicKey.export({ ...publicKey.algorithm, hash: "SHA-256" }, ["verify"], this.crypto);
            result = { id: Convert.ToHex(await this.crypto.subtle.exportKey("spki", key)), key };
          } else keyErrors.set(node.id, unchecked("unsupported-algorithm", new Error("Unsupported Google Cloud HSM certificate public key.")));
        } catch (error) {
          if (compatibleAlgorithm) normalizationError ??= asError(error);
          keyErrors.set(node.id, compatibleAlgorithm ? uncheckable(error) : unchecked("unsupported-algorithm", asError(error)));
        }
        normalized.set(node.id, result);
        return result;
      };
      const manufacturerKey = await keyOf({ certificate: manufacturerRoot, id: certificateId(manufacturerRoot) });
      const ownerKey = await keyOf({ certificate: ownerRoot, id: certificateId(ownerRoot) });
      if (!manufacturerKey || !ownerKey) {
        const issue = keyErrors.get(!manufacturerKey ? certificateId(manufacturerRoot) : certificateId(ownerRoot))!;
        return unverified(
          issue.status === "passed" ? "verification-error" : issue.reason,
          new Error("Unsupported Google Cloud HSM trust-anchor key.", { cause: issue.status === "passed" ? undefined : issue.error }),
        );
      }
      if (manufacturerKey.id === ownerKey.id) return unverified("invalid-trust-configuration", new Error("Google Cloud HSM requires independent manufacturer and owner trust keys."));

      const groups = new Map<string, VerificationCandidate & { compatible: boolean }>();
      const groupOf = new Map<string, VerificationCandidate & { compatible: boolean }>();
      // Signature evaluation is independent of four-role completion and cached once per normalized key.
      for (const node of nodes) {
        const key = await keyOf(node);
        let compatible = false;
        let id = key?.id ?? node.id;
        try {
          compatible = node.certificate.publicKey.algorithm.name === "RSASSA-PKCS1-v1_5";
          id = key?.id ?? Convert.ToHex(node.certificate.publicKey.rawData);
        } catch {
          /* Unreadable keys remain unsupported candidates. */
        }
        let group = groups.get(id);
        if (!group) {
          let signature: MarvellVerificationCheck = keyErrors.get(node.id) ?? unchecked("unsupported-algorithm", new Error("The evidence signature requires an RSA signing key."));
          if (compatible && key) {
            try {
              signature = (await this.crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key.key, attestation.signature as BufferSource, attestation.signedData as BufferSource))
                ? { status: "passed" }
                : rejected("invalid-signature", new Error("Failed to verify the attestation signature."));
            } catch (error) {
              signature = uncheckable(error);
            }
          }
          group = { certificates: [], signature, compatible };
          groups.set(id, group);
        }
        group.certificates.push(node.certificate);
        groupOf.set(node.id, group);
      }

      const edges = new Map<string, boolean>();
      let edgeError: Error | undefined;
      const issuedBy = async (child: CertificateNode, issuer: CertificateNode): Promise<boolean> => {
        const id = `${child.id}:${issuer.id}`;
        if (edges.has(id)) return edges.get(id)!;
        let ok = false;
        try {
          if (child.id !== issuer.id && child.certificate.issuer === issuer.certificate.subject) {
            ok = await child.certificate.verify({ publicKey: issuer.certificate.publicKey, signatureOnly: true }, this.crypto);
          }
        } catch (error) {
          edgeError ??= asError(error);
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
      for (const card of cards) {
        const cardKey = await keyOf(card);
        const ownerCards = cardKey && ownerCertificates.get(cardKey.id);
        if (!ownerCards) continue;
        for (const partition of nodes) {
          if (!(await issuedBy(partition, card))) continue;
          const partitionKey = await keyOf(partition);
          const ownerPartitions = partitionKey && ownerCertificates.get(partitionKey.id);
          if (!partitionKey || !ownerPartitions || !distinctOwners(card, partition, ownerCards, ownerPartitions)) continue;
          const group = groupOf.get(partition.id)!;
          group.trust = { status: "passed" };
          group.chain ??= [manufacturerRoot, card.certificate, partition.certificate];
          if (group.signature.status === "passed") return verified(partition.certificate, group.chain);
        }
      }
      const all = [...groups.values()];
      const incomplete = edgeError ?? normalizationError;
      const relationshipError = new Error("Failed to verify Google Cloud HSM card/partition certificate relationships.");
      for (const group of all) group.trust ??= incomplete ? uncheckable(incomplete) : rejected("untrusted-certificates", relationshipError);
      const relevant = all.filter((group) => group.compatible || group.trust?.status === "passed");
      const candidates = relevant.length ? relevant : all;
      const relationshipsFound = all.some((group) => group.trust?.status === "passed");
      return verificationFailure(candidates, relationshipsFound ? new Error("Failed to verify the attestation signature.") : relationshipError);
    } catch (error) {
      return unverified(error instanceof CertificateLimitError ? "resource-limit" : stage, error);
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
