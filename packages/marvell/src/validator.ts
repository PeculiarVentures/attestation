import * as x509 from "@peculiar/x509";
import { hex, isBufferSource } from "@peculiar/utils";
import type { MarvellAttestation } from "./attestation";
import { MarvellAttestationParser } from "./parser";
import { MANUFACTURER_ROOT_CERT, OWNER_ROOT_CERT } from "./certs";
import { CertificateLimitError, prepareCertificates } from "./certificates";
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

const MAX_CHAIN_ATTEMPTS = 128;
const CHAIN_LIMITS = { maxDepth: 16, maxSearchSteps: 10_000 };
interface ChainSearchBudget {
  remainingAttempts: number;
}

export interface MarvellAttestationValidatorParams {
  crypto?: Crypto;
  trustedCerts?: x509.X509Certificate[];
}

/* eslint-disable no-await-in-loop -- Searches share a request budget; acceptance searches precede failure diagnostics. */
export class MarvellAttestationValidator {
  private crypto: Crypto;
  private rootCerts: x509.X509Certificate[];

  constructor(params: MarvellAttestationValidatorParams = {}) {
    this.crypto = params.crypto || crypto;
    this.rootCerts = params.trustedCerts || [MANUFACTURER_ROOT_CERT, OWNER_ROOT_CERT];
    if (this.rootCerts.length < 2) throw new Error("Invalid number of root certificates. At least two certificates are required.");
  }

  /** Validates the evidence signature and paths to every configured root, with independent check results. */
  public async validate(data: Uint8Array | MarvellAttestation, certs: x509.X509Certificate[]): Promise<MarvellAttestationVerificationResult> {
    let stage: "malformed-evidence" | "verification-error" = "verification-error";
    try {
      const certificates = prepareCertificates(certs, this.rootCerts);
      stage = "malformed-evidence";
      const attestation = isBufferSource(data) ? new MarvellAttestationParser().parse(data as BufferSource) : (data as MarvellAttestation);
      assertEvidence(attestation);
      stage = "verification-error";
      const anchors = new Set(this.rootCerts.map((cert) => hex.encode(cert.rawData)));
      const groups = new Map<string, { certificates: x509.X509Certificate[]; compatible: boolean }>();
      let unreadableKey = false;
      for (const cert of certificates) {
        if (anchors.has(hex.encode(cert.rawData))) continue;
        try {
          const id = hex.encode(cert.publicKey.rawData);
          const group = groups.get(id);
          if (group) group.certificates.push(cert);
          // Preserve the generic validator's existing x509 RSA-PSS-to-PKCS1 export behavior.
          else groups.set(id, { certificates: [cert], compatible: cert.publicKey.algorithm.name.includes("RSA") });
        } catch {
          unreadableKey = true;
        }
      }
      const all = [...groups.values()];
      const compatible = all.filter((group) => group.compatible);
      const eligible = compatible.length ? compatible : all;
      const candidates: VerificationCandidate[] = [];
      const builder = new x509.X509ChainBuilder({ certificates });
      const budget: ChainSearchBudget = { remainingAttempts: MAX_CHAIN_ATTEMPTS };
      for (const group of eligible) {
        const signature = group.compatible
          ? await this.verifySignature(group.certificates[0], attestation)
          : unchecked("unsupported-algorithm", new Error("The evidence signature requires an RSA signing key."));
        const candidate: VerificationCandidate = { certificates: group.certificates, signature };
        candidates.push(candidate);
        if (signature.status === "passed") {
          await this.checkTrust(candidate, builder, budget);
          if (candidate.trust?.status === "passed") return verified(candidate.chain![candidate.chain!.length - 1], candidate.chain!);
        }
      }
      // Only diagnose mismatching/uncheckable keys after the original acceptance search is complete.
      if (!candidates.some((candidate) => candidate.signature.status === "passed")) {
        for (const candidate of candidates) await this.checkTrust(candidate, builder, budget);
      }
      if (!candidates.length && unreadableKey) return unverified("unsupported-algorithm", new Error("No usable certificate public key was supplied."));
      const signed = candidates.some((candidate) => candidate.signature.status === "passed");
      return verificationFailure(candidates, new Error(signed ? "Failed to build certificate chain for root certificate" : "Failed to verify the attestation signature."));
    } catch (error) {
      return unverified(error instanceof CertificateLimitError ? "resource-limit" : stage, error);
    }
  }

  private async checkTrust(candidate: VerificationCandidate, builder: x509.X509ChainBuilder, budget: ChainSearchBudget): Promise<void> {
    try {
      let primaryPath: x509.X509Certificate[] | undefined;
      for (const root of this.rootCerts) {
        const path = await this.getCertificateChain(root, candidate.certificates, builder, budget);
        if (!path) {
          candidate.trust = rejected("untrusted-certificates", new Error("Failed to build certificate chain for root certificate"));
          return;
        }
        primaryPath ??= path;
      }
      candidate.chain = [...primaryPath!].reverse();
      candidate.trust = { status: "passed" };
    } catch (error) {
      const limited = error instanceof CertificateLimitError || (error instanceof x509.X509ChainBuildError && error.code === "LIMIT_EXCEEDED");
      candidate.trust = unchecked(limited ? "resource-limit" : "verification-error", asError(error));
    }
  }

  private async getCertificateChain(root: x509.X509Certificate, candidates: x509.X509Certificate[], builder: x509.X509ChainBuilder, budget: ChainSearchBudget): Promise<x509.X509Certificate[] | null> {
    let incomplete: Error | undefined;
    for (const signer of candidates) {
      if (budget.remainingAttempts === 0) throw new CertificateLimitError(`Certificate chain search exceeded the ${MAX_CHAIN_ATTEMPTS}-attempt limit.`);
      budget.remainingAttempts--;
      try {
        const path = await builder.buildToAnchor(signer, { trustAnchors: root, limits: CHAIN_LIMITS }, this.crypto);
        if (path.length > 1) return path;
      } catch (error) {
        if (!(error instanceof x509.X509ChainBuildError)) throw error;
        if (error.code === "LIMIT_EXCEEDED") {
          if (!(incomplete instanceof x509.X509ChainBuildError) || incomplete.code !== "LIMIT_EXCEEDED") incomplete = error;
        } else if (error.rejectionsTruncated || error.rejections.some((rejection) => rejection.reason === "VERIFICATION_ERROR")) incomplete ??= error;
      }
    }
    if (incomplete) throw incomplete;
    return null;
  }

  private async verifySignature(cert: x509.X509Certificate, evidence: MarvellAttestation): Promise<MarvellVerificationCheck> {
    try {
      const algorithm = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
      const key = await cert.publicKey.export(algorithm, ["verify"], this.crypto);
      return (await this.crypto.subtle.verify(algorithm, key, evidence.signature as BufferSource, evidence.signedData as BufferSource))
        ? { status: "passed" }
        : rejected("invalid-signature", new Error("Failed to verify the attestation signature."));
    } catch (error) {
      return uncheckable(error);
    }
  }
}
/* eslint-enable no-await-in-loop */
