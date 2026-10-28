import { X509Certificate, PublicKey } from "@peculiar/x509";

export interface Attestation<T = unknown> {
  format: string;
  publicKey: PublicKey;
  metadata: T;
}

export interface AttestationVerificationParams {
  attestation: Attestation;
  /** Untrusted certificates available for certificate-path construction. */
  intermediateCerts: X509Certificate[];
  /**
   * Trust anchors for this call, replacing the provider's defaults rather than extending them.
   * Omit or pass undefined to use defaults. An empty array must not fall back to default trust.
   * Provider-specific requirements, such as the number of required anchors, still apply.
   */
  trustedCerts?: X509Certificate[];
}

export interface AttestationVerificationSuccess {
  status: true;
  chain: X509Certificate[];
  signer: X509Certificate;
}

export interface AttestationVerificationFailure {
  status: false;
  error: Error;
  signer?: X509Certificate;
  chain?: X509Certificate[];
}

export type AttestationVerificationResult = AttestationVerificationSuccess | AttestationVerificationFailure;

/**
 * Interface representing an attestation provider.
 * This utility allows working with various attestation formats.
 */
export interface AttestationProvider {
  /**
   * The format of the attestation.
   */
  format: string;

  /**
   * Reads the attestation data from the provided buffer source.
   *
   * @param data - The buffer source containing the attestation data.
   * @returns A promise that resolves to an Attestation object.
   */
  read(data: BufferSource): Promise<Attestation>;

  /**
   * Verifies the attestation using the provided verification parameters.
   *
   * @param params - The parameters required for attestation verification.
   * @returns A promise that resolves to an AttestationVerificationResult object.
   */
  verify(params: AttestationVerificationParams): Promise<AttestationVerificationResult>;
}
