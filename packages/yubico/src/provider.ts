import * as x509 from '@peculiar/x509';
import {
  Attestation,
  AttestationProvider,
  AttestationVerificationParams,
  AttestationVerificationResult,
} from '@peculiar/attestation-common';
import { YUBICO_ROOT_CERT } from './certs';

export type PivAttestation = Attestation<x509.X509Certificate>;

export class PivAttestationProvider implements AttestationProvider {
  format = 'piv';

  async read(data: BufferSource): Promise<Attestation> {
    const cert = new x509.X509Certificate(data);
    return {
      format: this.format,
      publicKey: cert.publicKey,
      metadata: cert,
    };
  }

  public getDefaultRootCert(): x509.X509Certificate {
    return YUBICO_ROOT_CERT;
  }

  async verify(
    params: AttestationVerificationParams,
  ): Promise<AttestationVerificationResult> {
    const trustedCerts = params.trustedCerts || [YUBICO_ROOT_CERT];
    const chainBuilder = new x509.X509ChainBuilder({
      certificates: [...params.intermediateCerts, ...trustedCerts],
    });
    const chain = await chainBuilder.build(
      params.attestation.metadata as x509.X509Certificate,
    );

    const rootCert = chain[chain.length - 1];
    if (trustedCerts.some((cert) => cert.equal(rootCert))) {
      return {
        status: true,
        chain,
        signer: chain[0],
      };
    }

    return {
      status: false,
      error: new Error(
        'Failed to verify the attestation chain. Root certificate is not trusted.',
      ),
      signer: chain[0],
      chain,
    };
  }
}
