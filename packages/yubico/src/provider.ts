import * as x509 from "@peculiar/x509";
import type { Attestation, AttestationProvider, AttestationVerificationParams, AttestationVerificationResult } from "@peculiar/attestation-common";
import { YUBICO_ROOT_CERT, YUBICO_ROOT_CERTS, YUBICO_INTERMEDIATE_CERTS } from "./certs";

export type PivAttestation = Attestation<x509.X509Certificate>;

export class PivAttestationProvider implements AttestationProvider {
  format = "piv";

  async read(data: BufferSource): Promise<Attestation> {
    const cert = new x509.X509Certificate(data);
    return {
      format: this.format,
      publicKey: cert.publicKey,
      metadata: cert,
    };
  }

  /**
   * Returns the legacy Yubico PIV root certificate.
   * @deprecated Use getDefaultRootCerts() to trust both legacy and newer YubiKeys.
   */
  public getDefaultRootCert(): x509.X509Certificate {
    return YUBICO_ROOT_CERT;
  }

  /** Returns all bundled production Yubico root certificates. */
  public getDefaultRootCerts(): x509.X509Certificate[] {
    return [...YUBICO_ROOT_CERTS];
  }

  async verify(params: AttestationVerificationParams): Promise<AttestationVerificationResult> {
    const trustedCerts = params.trustedCerts ?? this.getDefaultRootCerts();
    const chainBuilder = new x509.X509ChainBuilder({
      certificates: [...params.intermediateCerts, ...YUBICO_INTERMEDIATE_CERTS, ...trustedCerts],
    });
    const chain = await chainBuilder.build(params.attestation.metadata as x509.X509Certificate);

    // Bundled issuers may extend the path above an explicitly pinned trust anchor.
    const trustedIndex = chain.findIndex((cert) => trustedCerts.some((trusted) => trusted.equal(cert)));
    if (trustedIndex !== -1) {
      return {
        status: true,
        chain: chain.slice(0, trustedIndex + 1),
        signer: chain[0],
      };
    }

    return {
      status: false,
      error: new Error("Failed to verify the attestation chain. Root certificate is not trusted."),
      signer: chain[0],
      chain,
    };
  }
}
