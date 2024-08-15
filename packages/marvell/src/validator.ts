import { AttestationVerificationResult } from '@peculiar/attestation-common';
import x509 from '@peculiar/x509';
import { MarvellAttestation } from './attestation';
import { MarvellAttestationParser } from './parser';
import { BufferSourceConverter } from 'pvtsutils';
import { MANUFACTURER_ROOT_CERT, OWNER_ROOT_CERT } from './certs';

export interface MarvellAttestationValidatorParams {
  crypto?: Crypto;
  mfrRootCert?: x509.X509Certificate;
  ownerRootCert?: x509.X509Certificate;
}

export interface ValidationResult {
  isValid: boolean;
  signer: x509.X509Certificate;
  chain: x509.X509Certificates;
}

export class MarvellAttestationValidator {
  private crypto: Crypto;
  private mfrRootCert: x509.X509Certificate;
  private ownerRootCert: x509.X509Certificate;

  constructor(params: MarvellAttestationValidatorParams = {}) {
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
   * @returns A promise that resolves with an object containing the validation result.
   */
  public async validate(
    data: Uint8Array | MarvellAttestation,
    certs: x509.X509Certificate[],
  ): Promise<AttestationVerificationResult> {
    try {
      const parser = new MarvellAttestationParser();
      const attestation = BufferSourceConverter.isBufferSource(data)
        ? parser.parse(data)
        : data;

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
      const isValid = await this.verifyAttestation(
        mfrPartitionCert,
        signature,
        signedData,
      );

      if (isValid) {
        const result: AttestationVerificationResult = {
          status: true,
          signer: mfrPartitionCert,
          chain: certs,
        };
        return result;
      } else {
        const result: AttestationVerificationResult = {
          status: false,
          error: new Error('Failed to verify the attestation signature.'),
          signer: mfrPartitionCert,
          chain: certs,
        };
        return result;
      }
    } catch (error) {
      const result: AttestationVerificationResult = {
        status: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
      return result;
    }
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
