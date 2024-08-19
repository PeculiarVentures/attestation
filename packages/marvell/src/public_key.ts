import {
  AlgorithmProvider,
  diAlgorithmProvider,
  PublicKey,
} from '@peculiar/x509';
import { SubjectPublicKeyInfo } from '@peculiar/asn1-x509';
import { RSAPublicKey } from '@peculiar/asn1-rsa';
import { AsnConvert } from '@peculiar/asn1-schema';
import { container } from 'tsyringe';
import { CryptokiKeyType, MarvellAttestation } from './attestation';

/**
 * Interface representing the algorithm and key usages.
 */
export interface AlgorithmAndKeyUsages {
  algorithm: Algorithm;
  keyUsages: KeyUsage[];
}

/**
 * Class to handle operations related to MarvellProvider.
 */
export class PublicKeyExtractor {
  public crypto: Crypto = crypto;

  /**
   * Determines the algorithm and key usages based on the attestation.
   * @param attestation - The KmsAttestation object.
   * @returns The algorithm and key usages.
   */
  private determineAlgorithmAndKeyUsages(
    attestation: MarvellAttestation,
  ): AlgorithmAndKeyUsages {
    const attrs = attestation.attestationData.firstKey.attributes;
    const keyType = CryptokiKeyType[attrs['OBJ_ATTR_KEY_TYPE']];
    let algorithm:
      | Algorithm
      | RsaHashedImportParams
      | EcKeyImportParams
      | undefined;
    let keyUsages: KeyUsage[];

    switch (keyType) {
      case CryptokiKeyType.CKK_RSA:
        if (attrs['OBJ_ATTR_VERIFY'] || attrs['OBJ_ATTR_SIGN']) {
          algorithm = { name: 'RSASSA-PKCS1-v1_5' };
          keyUsages = ['verify'];
        } else {
          algorithm = { name: 'RSA-OAEP' };
          keyUsages = ['encrypt', 'wrapKey'];
        }
        break;
      case CryptokiKeyType.CKK_EC: {
        const algName =
          attrs['OBJ_ATTR_VERIFY'] || attrs['OBJ_ATTR_SIGN'] ? 'ECDSA' : 'ECDH';
        keyUsages =
          algName === 'ECDSA' ? ['verify'] : ['deriveKey', 'deriveBits'];
        const valueLen = attrs['OBJ_ATTR_VALUE_LEN'];
        switch (valueLen) {
          case 65:
            algorithm = { name: algName, namedCurve: 'P-256' };
            break;
          case 97:
            algorithm = { name: algName, namedCurve: 'P-384' };
            break;
          case 133:
            algorithm = { name: algName, namedCurve: 'P-521' };
            break;
          default:
            throw new Error('Unsupported curve');
        }
        break;
      }
      default:
        throw new Error('Unsupported key type');
    }

    return { algorithm, keyUsages };
  }

  /**
   * Converts the attestation to PKCS#8 format.
   * @param attestation - The KmsAttestation object.
   * @returns The PKCS#8 formatted ArrayBuffer.
   */
  private attestToPkcs8(attestation: MarvellAttestation): ArrayBuffer {
    const { algorithm } = this.determineAlgorithmAndKeyUsages(attestation);
    const attributes = attestation.attestationData.firstKey.attributes;
    const modulus = attributes['OBJ_ATTR_MODULUS'];

    let subjectPublicKey: ArrayBuffer = modulus;
    if (algorithm.name.startsWith('RSA')) {
      const rsaPublicKey = new RSAPublicKey({
        modulus: modulus,
        publicExponent: attributes['OBJ_ATTR_PUBLIC_EXPONENT'],
      });
      subjectPublicKey = AsnConvert.serialize(rsaPublicKey);
    }

    const spki = new SubjectPublicKeyInfo({
      algorithm: container
        .resolve<AlgorithmProvider>(diAlgorithmProvider)
        .toAsnAlgorithm(algorithm),
      subjectPublicKey,
    });

    return AsnConvert.serialize(spki);
  }

  /**
   * Extracts the public key from the attestation.
   * @param attestation - The KmsAttestation object containing the attestation data.
   * @returns The PublicKey object derived from the attestation.
   */
  public extractPublicKey(attestation: MarvellAttestation): PublicKey {
    const pkcs8 = this.attestToPkcs8(attestation);
    return new PublicKey(pkcs8);
  }
}
