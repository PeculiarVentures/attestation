import { type AttestationVerificationResult } from "@peculiar/attestation-common";
import * as x509 from "@peculiar/x509";
import { BufferSourceConverter, Convert } from "pvtsutils";
import { type MarvellAttestation } from "./attestation";
import { MarvellAttestationParser } from "./parser";
import { MANUFACTURER_ROOT_CERT, OWNER_ROOT_CERT } from "./certs";
import { prepareCertificates } from "./certificates";

// Bound preparation and repeated searches as well as each individual x509 traversal.
const MAX_CHAIN_ATTEMPTS = 128;
const CHAIN_LIMITS = { maxDepth: 16, maxSearchSteps: 10_000 };

interface ChainSearchBudget {
  remainingAttempts: number;
}

export interface MarvellAttestationValidatorParams {
  crypto?: Crypto;
  trustedCerts?: x509.X509Certificate[];
}

/* eslint-disable no-await-in-loop -- Searches share a request budget and stop as soon as a candidate is accepted. */
export class MarvellAttestationValidator {
  private crypto: Crypto;
  private rootCerts: x509.X509Certificate[];

  constructor(params: MarvellAttestationValidatorParams = {}) {
    this.crypto = params.crypto || crypto;
    this.rootCerts = params.trustedCerts || [MANUFACTURER_ROOT_CERT, OWNER_ROOT_CERT];
    if (this.rootCerts.length < 2) {
      throw new Error("Invalid number of root certificates. At least two certificates are required.");
    }
  }

  /**
   * Validates the attestation signature and paths to every configured root.
   * @param data - The attestation data to validate.
   * @param certs - Candidate signing and intermediate certificates.
   * @returns A promise that resolves with the validation result; chain is in root-to-signer order.
   */
  public async validate(data: Uint8Array | MarvellAttestation, certs: x509.X509Certificate[]): Promise<AttestationVerificationResult> {
    try {
      const certificates = prepareCertificates(certs, this.rootCerts);
      const anchors = new Set(this.rootCerts.map((cert) => Convert.ToHex(cert.rawData)));
      const signers = new Map<string, x509.X509Certificate[]>();
      for (const cert of certificates) {
        // An anchor alone must not become an attestation signing certificate.
        if (anchors.has(Convert.ToHex(cert.rawData))) {
          continue;
        }
        let key: string;
        try {
          key = Convert.ToHex(cert.publicKey.rawData);
        } catch {
          // A malformed or unsupported key in an unrelated certificate must not discard valid paths.
          continue;
        }
        const group = signers.get(key);
        if (group) {
          group.push(cert);
        } else {
          signers.set(key, [cert]);
        }
      }

      const attestation = BufferSourceConverter.isBufferSource(data) ? new MarvellAttestationParser().parse(data as BufferSource) : (data as MarvellAttestation);
      const builder = new x509.X509ChainBuilder({ certificates });
      const budget: ChainSearchBudget = { remainingAttempts: MAX_CHAIN_ATTEMPTS };
      let signatureVerified = false;
      for (const candidates of signers.values()) {
        // Certificates for the same partition can differ between roots but share one SPKI.
        let validSignature: boolean;
        try {
          validSignature = await this.verifyAttestation(candidates[0], attestation.signature, attestation.signedData);
        } catch {
          // Unrelated certificates may have keys incompatible with the evidence signature format.
          continue;
        }
        if (!validSignature) {
          continue;
        }
        signatureVerified = true;

        let primaryPath: x509.X509Certificate[] | undefined;
        let allRootsReached = true;
        for (const root of this.rootCerts) {
          // An anchor array in buildToAnchor() means ANY anchor; Marvell requires EVERY root.
          const path = await this.getCertificateChain(root, candidates, builder, budget);
          if (!path) {
            allRootsReached = false;
            break;
          }
          primaryPath ??= path;
        }
        if (allRootsReached && primaryPath) {
          return { status: true, signer: primaryPath[0], chain: [...primaryPath].reverse() };
        }
      }

      return {
        status: false,
        error: new Error(signatureVerified ? "Failed to build certificate chain for root certificate" : "Failed to verify the attestation signature."),
      };
    } catch (error) {
      return { status: false, error: error instanceof Error ? error : new Error(String(error)) };
    }
  }

  private async getCertificateChain(root: x509.X509Certificate, candidates: x509.X509Certificate[], builder: x509.X509ChainBuilder, budget: ChainSearchBudget): Promise<x509.X509Certificate[] | null> {
    let limited: x509.X509ChainBuildError | undefined;
    for (const signer of candidates) {
      if (budget.remainingAttempts === 0) {
        throw new Error(`Certificate chain search exceeded the ${MAX_CHAIN_ATTEMPTS}-attempt limit.`);
      }
      budget.remainingAttempts--;
      try {
        const path = await builder.buildToAnchor(signer, { trustAnchors: root, limits: CHAIN_LIMITS }, this.crypto);
        if (path.length > 1) {
          return path;
        }
      } catch (error) {
        if (!(error instanceof x509.X509ChainBuildError)) {
          throw error;
        }
        if (error.code === "LIMIT_EXCEEDED") {
          // A different certificate for this key may have a short, complete path.
          limited ??= error;
        }
      }
    }
    if (limited) {
      throw limited;
    }
    return null;
  }

  private async verifyAttestation(cert: x509.X509Certificate, signature: Uint8Array, signedData: Uint8Array): Promise<boolean> {
    const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
    const publicKey = await cert.publicKey.export(alg, ["verify"], this.crypto);
    return this.crypto.subtle.verify(alg, publicKey, signature as BufferSource, signedData as BufferSource);
  }
}
/* eslint-enable no-await-in-loop */
