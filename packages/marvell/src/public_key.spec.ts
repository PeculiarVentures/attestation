import assert from 'node:assert';
import { PublicKeyExtractor } from './public_key';
import {
  Attributes,
  MarvellAttestation,
  MarvellAttestationFlags,
} from './attestation';

describe('Marvell:PublicKeyExtractor', () => {
  const data = Buffer.from('test data to sign');
  const hash = 'SHA-256';
  const vector: {
    name: string;
    algorithm: RsaHashedKeyGenParams | EcKeyGenParams;
  }[] = [
    {
      name: 'RSASSA-PKCS1-v1_5 2048',
      algorithm: {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash,
      },
    },
    {
      name: 'ECDSA P-256',
      algorithm: {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
    },
    {
      name: 'ECDSA P-384',
      algorithm: {
        name: 'ECDSA',
        namedCurve: 'P-384',
      },
    },
    {
      name: 'ECDSA P-521',
      algorithm: {
        name: 'ECDSA',
        namedCurve: 'P-521',
      },
    },
  ];

  const extractor = new PublicKeyExtractor();

  vector.forEach((item) => {
    it(`should extract the public key for ${item.name}`, async () => {
      const keys = await crypto.subtle.generateKey(item.algorithm, true, [
        'sign',
        'verify',
      ]);
      const signingAlgorithm = { hash, ...item.algorithm };
      const signature = await crypto.subtle.sign(
        signingAlgorithm,
        keys.privateKey,
        data,
      );

      const attributes = {} as Attributes;
      if (item.algorithm.name.startsWith('RSA')) {
        const jwk = await crypto.subtle.exportKey('jwk', keys.publicKey);
        attributes.OBJ_ATTR_KEY_TYPE = 'CKK_RSA';
        attributes.OBJ_ATTR_VERIFY = true;
        attributes.OBJ_ATTR_MODULUS = Buffer.from(jwk.n!, 'base64url');
        attributes.OBJ_ATTR_PUBLIC_EXPONENT = Buffer.from(jwk.e!, 'base64url');
      } else {
        const raw = await crypto.subtle.exportKey('raw', keys.publicKey);
        attributes.OBJ_ATTR_KEY_TYPE = 'CKK_EC';
        attributes.OBJ_ATTR_VERIFY = true;
        attributes.OBJ_ATTR_VALUE_LEN = raw.byteLength;
        attributes.OBJ_ATTR_MODULUS = new Uint8Array(raw);
      }

      const attest: MarvellAttestation = {
        compressed: false,
        responseHeader: {
          bufferSize: 0,
          requestFlags: MarvellAttestationFlags.KEY_GEN_FLAG_GET_ATTEST,
          responseCode: 0,
          totalSize: 0,
        },
        attestationData: {
          info: {
            objectVersion: 0,
            offsetFirstKey: 0,
            offsetSecondKey: 0,
            requestFlags: 0,
          },
          firstKey: {
            attributeCount: 0,
            handle: 0,
            objectSize: 0,
            attributes,
          },
        },
        signature: new Uint8Array(0),
        signedData: new Uint8Array(0),
      };

      const publicKey = extractor.extractPublicKey(attest);
      const key = await publicKey.export(signingAlgorithm, ['verify']);
      const ok = await crypto.subtle.verify(
        signingAlgorithm,
        key,
        signature,
        data,
      );
      assert.strictEqual(ok, true);
    });
  });
});
