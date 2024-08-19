import { AttestationVerificationResult } from '@peculiar/attestation-common';
import x509 from '@peculiar/x509';
import { BufferSourceConverter } from 'pvtsutils';
import { MarvellAttestation } from './attestation';
import { MarvellAttestationParser } from './parser';
import { MANUFACTURER_ROOT_CERT, OWNER_ROOT_CERT } from './certs';

export interface MarvellAttestationValidatorParams {
  crypto?: Crypto;
  trustedCerts?: x509.X509Certificate[];
}

export class MarvellAttestationValidator {
  private crypto: Crypto;
  private rootCerts: x509.X509Certificate[];

  constructor(params: MarvellAttestationValidatorParams = {}) {
    this.crypto = params.crypto || crypto;
    this.rootCerts = params.trustedCerts || [
      MANUFACTURER_ROOT_CERT,
      OWNER_ROOT_CERT,
    ];
    if (this.rootCerts.length < 2) {
      throw new Error(
        'Invalid number of root certificates. At least two certificates are required.',
      );
    }
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
      let attestation: MarvellAttestation;
      if (BufferSourceConverter.isBufferSource(data)) {
        const parser = new MarvellAttestationParser();
        attestation = parser.parse(data);
      } else {
        attestation = data;
      }

      // Build certificate chains for all root certificates
      const chains = [];
      for (const rootCert of this.rootCerts) {
        const chain = await this.getCertificateChain(rootCert, certs);
        if (!chain) {
          throw new Error(
            'Failed to build certificate chain for root certificate',
          );
        }
        chains.push(chain);
      }

      const chain = chains[0];
      const leafCerts = chains.map((chain) => chain[chain.length - 1]);

      // Check if all public keys match
      const signer = leafCerts[0];
      const keyId = await signer.publicKey.getKeyIdentifier(this.crypto);
      for (const cert of leafCerts) {
        const certKeyId = await cert.publicKey.getKeyIdentifier(this.crypto);
        if (!BufferSourceConverter.isEqual(keyId, certKeyId)) {
          throw new Error(
            'Public key mismatch between leaf certificates in different chains',
          );
        }
      }

      const signature = attestation.signature;
      const signedData = attestation.signedData;

      // Perform a single signature verification
      const isValid = await this.verifyAttestation(
        leafCerts[0],
        signature,
        signedData,
      );

      if (isValid) {
        const result: AttestationVerificationResult = {
          status: true,
          signer,
          chain,
        };
        return result;
      } else {
        const result: AttestationVerificationResult = {
          status: false,
          error: new Error('Failed to verify the attestation signature.'),
          signer,
          chain,
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

  private async getCertificateChain(
    rootCert: x509.X509Certificate,
    certs: x509.X509Certificate[],
  ): Promise<x509.X509Certificate[] | null> {
    const chain: x509.X509Certificate[] = [rootCert];
    let currentCert = rootCert;

    while (true) {
      const issuedCert = await this.getIssuedCertificate(currentCert, certs);
      if (!issuedCert) {
        break;
      }
      chain.push(issuedCert);
      currentCert = issuedCert;
    }

    return chain.length > 1 ? chain : null;
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
