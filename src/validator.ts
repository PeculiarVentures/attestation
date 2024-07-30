import x509 from '@peculiar/x509';
import { KmsAttestation } from './attestation';
import { KmsAttestationParser } from './parser';
import { BufferSourceConverter } from 'pvtsutils';
import { MANUFACTURER_ROOT_CERT, OWNER_ROOT_CERT } from './certs';

export interface KmsAttestationValidatorParams {
  crypto?: Crypto;
  mfrRootCert?: x509.X509Certificate;
  ownerRootCert?: x509.X509Certificate;
}

export class KmsAttestationValidator {
  private crypto: Crypto;
  private mfrRootCert: x509.X509Certificate;
  private ownerRootCert: x509.X509Certificate;

  constructor(params: KmsAttestationValidatorParams = {}) {
    this.crypto = params.crypto || crypto;
    this.mfrRootCert =
      params.mfrRootCert || this.getDefaultManufacturerRootCertificate();
    this.ownerRootCert =
      params.ownerRootCert || this.getDefaultOwnerRootCertificate();
  }

  /**
   * Validates the attestation data.
   * @param data - The attestation data to validate.
   * @param certChain - The certificate chain used to validate the attestation data.
   * @returns A promise that resolves with a boolean indicating whether the attestation data is valid.
   */
  public async validate(
    data: Uint8Array | KmsAttestation,
    certChain: string,
  ): Promise<boolean> {
    const parser = new KmsAttestationParser();
    const attestation = BufferSourceConverter.isBufferSource(data)
      ? parser.parse(data)
      : data;

    const certBlobs = x509.PemConverter.decode(certChain);
    const certs = certBlobs.map((blob) => new x509.X509Certificate(blob));

    const mfrCardCert = await this.getIssuedCertificate(
      this.mfrRootCert,
      certs,
    );
    if (!mfrCardCert) {
      throw new Error(
        'Failed to build the HSM manufacturer card certificate chain.',
      );
    }
    const mfrPartitionCert = await this.getIssuedCertificate(
      mfrCardCert,
      certs,
    );
    if (!mfrPartitionCert) {
      throw new Error(
        'Failed to build the HSM manufacturer partition certificate chain.',
      );
    }

    const ownerCardCert = await this.getIssuedCertificate(
      this.ownerRootCert,
      certs,
      (cert) => {
        return cert.publicKey.equal(mfrCardCert.publicKey);
      },
    );

    const ownerPartitionCert = await this.getIssuedCertificate(
      this.ownerRootCert,
      certs,
      (cert) => {
        return cert.publicKey.equal(mfrPartitionCert.publicKey);
      },
    );

    if (!ownerCardCert || !ownerPartitionCert) {
      throw new Error('Failed to build HSM owner certificate chain.');
    }

    // Check if public keys match
    if (!mfrPartitionCert.publicKey.equal(ownerPartitionCert.publicKey)) {
      throw new Error(
        'Public keys of manufacturer and owner partition certificates do not match.',
      );
    }

    const signature = attestation.signature;
    const signedData = attestation.signedData;

    // Perform a single signature verification
    return await this.verifyAttestation(
      mfrPartitionCert,
      signature,
      signedData,
    );
  }

  private getDefaultManufacturerRootCertificate(): x509.X509Certificate {
    return MANUFACTURER_ROOT_CERT;
  }

  private getDefaultOwnerRootCertificate(): x509.X509Certificate {
    return OWNER_ROOT_CERT;
  }

  private async getIssuedCertificate(
    rootCert: x509.X509Certificate,
    certs: x509.X509Certificate[],
    predicate?: (cert: x509.X509Certificate) => boolean,
  ): Promise<x509.X509Certificate | null> {
    for (const cert of certs) {
      if (cert.issuer === rootCert.subject && (!predicate || predicate(cert))) {
        const ok = await cert.verify({
          publicKey: rootCert.publicKey,
          signatureOnly: true,
        });
        if (!ok) {
          throw new Error('Failed to verify the certificate chain.');
        }
        return cert;
      }
    }
    return null;
  }

  private async verifyAttestation(
    cert: x509.X509Certificate,
    signature: Uint8Array,
    signedData: Uint8Array,
  ): Promise<boolean> {
    const alg = {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256',
    };
    const publicKey = await cert.publicKey.export(alg, ['verify'], this.crypto);
    return await this.crypto.subtle.verify(
      alg,
      publicKey,
      signature,
      signedData,
    );
  }
}
