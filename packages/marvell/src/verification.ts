import { type AttestationVerificationFailure, type AttestationVerificationSuccess } from "@peculiar/attestation-common";
import { type X509Certificate } from "@peculiar/x509";
import { BufferSourceConverter } from "pvtsutils";
import { type MarvellAttestation } from "./attestation";

export type MarvellVerificationReason =
  | "invalid-signature"
  | "untrusted-certificates"
  | "missing-signer"
  | "ambiguous-signer"
  | "malformed-evidence"
  | "unsupported-algorithm"
  | "invalid-trust-configuration"
  | "resource-limit"
  | "verification-error"
  | "invalid-format";

export type MarvellVerificationCheck = { status: "passed" } | { status: "failed" | "not-evaluated"; reason: MarvellVerificationReason; error: Error };

export type MarvellAttestationVerificationResult =
  | (AttestationVerificationSuccess & { signature: { status: "passed" }; trust: { status: "passed" } })
  | (AttestationVerificationFailure & {
      signature: MarvellVerificationCheck;
      trust: MarvellVerificationCheck;
      /** Diagnostic certificates for one signing-key group; this does not establish overall acceptance. */
      candidate?: { certificates: X509Certificate[]; chain?: X509Certificate[] };
    });

export interface VerificationCandidate {
  certificates: X509Certificate[];
  signature: MarvellVerificationCheck;
  trust?: MarvellVerificationCheck;
  chain?: X509Certificate[];
}

export function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

export function unchecked(reason: MarvellVerificationReason, error: Error): MarvellVerificationCheck {
  return { status: "not-evaluated", reason, error };
}

export function uncheckable(error: unknown): MarvellVerificationCheck {
  const cause = asError(error);
  return unchecked(cause.name === "NotSupportedError" ? "unsupported-algorithm" : "verification-error", cause);
}

export function rejected(reason: MarvellVerificationReason, error: Error): MarvellVerificationCheck {
  return { status: "failed", reason, error };
}

export function unverified(reason: MarvellVerificationReason, error: unknown): MarvellAttestationVerificationResult {
  const cause = asError(error);
  return { status: false, error: cause, signature: unchecked(reason, cause), trust: unchecked(reason, cause) };
}

export function verified(signer: X509Certificate, chain: X509Certificate[]): MarvellAttestationVerificationResult {
  return { status: true, signer, chain, signature: { status: "passed" }, trust: { status: "passed" } };
}

/** Validate the parsed input's cryptographic buffers without interpreting the attested key. */
export function assertEvidence(evidence: MarvellAttestation): void {
  if (!evidence || !BufferSourceConverter.isBufferSource(evidence.signedData) || !BufferSourceConverter.isBufferSource(evidence.signature)) {
    throw new TypeError("Invalid Marvell evidence: signedData and signature must be buffer sources.");
  }
}

function aggregateSignature(candidates: VerificationCandidate[]): MarvellVerificationCheck {
  const checks = candidates.map((candidate) => candidate.signature);
  if (!checks.length) return unchecked("missing-signer", new Error("No candidate evidence signing key was supplied."));
  if (checks.some((check) => check.status === "passed")) return { status: "passed" };
  if (checks.every((check) => check.status === "failed")) return rejected("invalid-signature", new Error("Failed to verify the attestation signature."));
  const unknown = checks.filter((check): check is Exclude<MarvellVerificationCheck, { status: "passed" }> => check.status === "not-evaluated");
  if (unknown.length === checks.length && unknown.every((check) => check.reason === unknown[0].reason)) return unknown[0];
  return unchecked("ambiguous-signer", new Error("Candidate signing keys have inconclusive verification results."));
}

function aggregateTrust(candidates: VerificationCandidate[]): MarvellVerificationCheck {
  const checks = candidates.map((candidate) => candidate.trust);
  if (checks.some((check) => check?.status === "passed")) return { status: "passed" };
  const unknown = checks.find((check) => check?.status === "not-evaluated" && check.reason === "resource-limit") ?? checks.find((check) => check?.status === "not-evaluated");
  if (unknown) return unknown;
  const failed = checks.find((check) => check?.status === "failed");
  return failed ?? unchecked("missing-signer", new Error("No candidate certificate policy could be evaluated."));
}

/** Both conclusions concern the same relevant key set; an unrelated trusted key cannot rescue a valid untrusted signature. */
export function verificationFailure(candidates: VerificationCandidate[], legacyError: Error): MarvellAttestationVerificationResult {
  const signed = candidates.filter((candidate) => candidate.signature.status === "passed");
  const trusted = candidates.filter((candidate) => candidate.trust?.status === "passed");
  const policyIncomplete = !signed.length && candidates.some((candidate) => candidate.trust?.status === "not-evaluated");
  const incompleteSearch = policyIncomplete && !candidates.every((candidate) => candidate.signature.status === "failed");
  const relevant = signed.length ? signed : incompleteSearch ? candidates : trusted.length ? trusted : candidates;
  const signature = aggregateSignature(relevant);
  const trust = aggregateTrust(relevant);
  const incomplete = [trust, signature].find((check) => check.status === "not-evaluated" && (check.reason === "resource-limit" || check.reason === "verification-error"));
  const error = incomplete && incomplete.status !== "passed" ? incomplete.error : legacyError;
  return {
    status: false,
    error,
    signature,
    trust,
    ...(relevant.length === 1 && (!policyIncomplete || candidates.length === 1)
      ? { candidate: { certificates: [...relevant[0].certificates], ...(relevant[0].chain ? { chain: [...relevant[0].chain] } : {}) } }
      : {}),
  };
}
