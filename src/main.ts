//!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import * as x509 from '@peculiar/x509';
import { Command } from 'commander';
import {
  KmsAttestation,
  ResponseHeader,
  KmsAttestationData,
  ObjectAttributes,
  AttributeMap,
  AttributeType,
  AttestationFlags,
} from './attestation';
import { KmsAttestationParser } from './parser';
import {
  KmsAttestationValidatorParams,
  KmsAttestationValidator,
} from './validator';

/**
 * Get the version of the package
 * @returns The version of the package
 */
function getVersion(): string {
  // Determine the base directory
  const baseDir = __dirname.endsWith('src')
    ? path.resolve(__dirname, '../') // Running from source when running via ts-node
    : path.resolve(__dirname, '../../'); // Running from build when running via node
  const packageJsonPath = path.join(baseDir, 'package.json');

  // Read and parse the package.json file
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
  return packageJson.version;
}

const program = new Command()
  .name('kms-attestation')
  .description('Utility for verifying KMS key attestation')
  .version(getVersion());

//#region Commands

program
  .command('verify')
  .description('Verify the key attestation')
  .option(
    '-c, --certs <file>',
    'The file containing the attestation certificates',
  )
  .option(
    '-m, --mfr <file>',
    'The file containing the manufacturer root certificate',
  )
  .option(
    '-o, --owner <file>',
    'The file containing the owner root certificate',
  )
  .option('--info', 'Output information about the attestation and certificates')
  .argument('<file>', 'The file containing the key attestation')
  .action(
    async (
      file: string,
      options: {
        certs: string;
        mfrRootCert?: string;
        ownerRootCert?: string;
        info?: boolean;
      },
    ) => {
      try {
        assertFileExists(file);
        const { certs, mfrRootCert, ownerRootCert, info } = options;
        assertCertsOption(certs);
        assertFileExists(certs);

        const attestation = fs.readFileSync(file);
        const certificates = fs.readFileSync(certs, 'utf-8');

        const validatorParams: KmsAttestationValidatorParams = {};

        if (mfrRootCert) {
          assertFileExists(mfrRootCert);
          validatorParams.mfrRootCert = new x509.X509Certificate(
            fs.readFileSync(mfrRootCert),
          );
        }

        if (ownerRootCert) {
          assertFileExists(ownerRootCert);
          validatorParams.ownerRootCert = new x509.X509Certificate(
            fs.readFileSync(ownerRootCert),
          );
        }

        const parser = new KmsAttestationParser();
        const attestationData = parser.parse(attestation);

        if (info) {
          printAttestation(attestationData);
        }

        const validator = new KmsAttestationValidator(validatorParams);
        const result = await validator.validate(attestationData, certificates);

        console.log('Attestation:', result ? 'PASSED' : 'FAILED');

        if (!result) {
          process.exit(1);
        }
      } catch (error) {
        program.error((error as Error).message);
      }
    },
  );

program
  .command('show-cert')
  .description('Display information about the attestation certificates')
  .argument('<file>', 'The file containing the attestation certificates')
  .action((file: string) => {
    if (!fs.existsSync(file)) {
      console.error(`File not found: ${file}`);
      process.exit(1);
    }

    const data = fs.readFileSync(file);
    const certBlobs = x509.PemConverter.decode(data.toString());
    const certs = certBlobs.map((blob) => new x509.X509Certificate(blob));

    for (const cert of certs) {
      console.log(cert.toString('text'));
    }
  });

program
  .command('show-info')
  .description('Display information about the key attestation')
  .argument('<file>', 'The file containing the key attestation')
  .action((file: string) => {
    assertFileExists(file);
    const data = fs.readFileSync(file);
    const attestation = new KmsAttestationParser().parse(data);

    printAttestation(attestation);
  });

//#endregion

//#region Assertion functions

function assertFileExists(filePath: string): void {
  if (!fs.existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }
}

function assertCertsOption(certs: string | undefined): void {
  if (!certs) {
    throw new Error('Missing required option: --certs');
  }
}

//#endregion

//#region Printing functions

const TAB = '  ';

function printAttestation(attestation: KmsAttestation, tab = '') {
  console.log(`${tab}Key Attestation:`);
  console.log(`${tab}${TAB}Compressed: ${attestation.compressed}`);
  printResponseHeader(attestation.responseHeader, tab + TAB);
  printAttestationData(attestation.attestationData, tab + TAB);
}

function printResponseHeader(attestation: ResponseHeader, tab = '') {
  console.log(`${tab}Response Header:`);
  console.log(`${tab}${TAB}Code: ${attestation.responseCode}`);
  console.log(
    `${tab}${TAB}Flags: ${stringifyAttestationFlags(attestation.requestFlags)}`,
  );
  console.log(`${tab}${TAB}Buffer Size: ${attestation.bufferSize} bytes`);
  console.log(`${tab}${TAB}Total Size: ${attestation.totalSize} bytes`);
}

function printAttestationData(attestation: KmsAttestationData, tab = '') {
  console.log(`${tab}Key Attestation Data:`);
  console.log(`${tab}${TAB}Version: v${attestation.info.objectVersion}`);
  console.log(
    `${tab}${TAB}Flags: ${stringifyAttestationFlags(
      attestation.info.requestFlags,
    )}`,
  );

  printObject(attestation.firstKey, 'First Key', tab + TAB);
  printObject(attestation.secondKey, 'Second Key', tab + TAB);
}

function printObject(
  data: ObjectAttributes,
  name = 'Object Attributes',
  tab = '',
) {
  console.log(`${tab}${name}:`);
  console.log(
    `${tab}${TAB}Handle: 0x${data.handle.toString(16).padStart(8, '0')}`,
  );
  console.log(`${tab}${TAB}Object Size: ${data.objectSize} bytes`);
  console.log(`${tab}${TAB}Attribute Count: ${data.attributeCount}`);

  printAttributes(data.attributes, tab + TAB);
}

function printAttributes(attributes: AttributeMap, tab = '') {
  console.log(`${tab}Attributes:`);
  for (const [, attribute] of Object.entries(attributes)) {
    const tag = attribute.tag;
    console.log(
      `${tab}${TAB}${AttributeType[attribute.tag]}: ${stringifyAttributeValue(
        attribute.tag,
        attribute.value,
      )}`,
    );
  }
}

enum CryptokiObjectClass {
  CKO_DATA = 0x00,
  CKO_CERTIFICATE = 0x01,
  CKO_PUBLIC_KEY = 0x02,
  CKO_PRIVATE_KEY = 0x03,
  CKO_SECRET_KEY = 0x04,
  CKO_HW_FEATURE = 0x05,
  CKO_DOMAIN_PARAMETERS = 0x06,
  CKO_MECHANISM = 0x07,
  CKO_OTP_KEY = 0x08,
}

function stringifyAttributeText(value: Uint8Array) {
  const nullByte = value.indexOf(0);
  return Buffer.from(value.subarray(0, nullByte)).toString();
}

function stringifyAttributeBoolean(value: Uint8Array) {
  return !!value[0];
}

function stringifyAttributeEnum<T>(value: Uint8Array, enumType: T) {
  return (
    (enumType as Record<number, string>)[value[0]] || `Unknown (${value[0]})`
  );
}

function stringifyAttributeNumber(value: Uint8Array) {
  return new DataView(
    value.buffer,
    value.byteOffset,
    value.byteLength,
  ).getUint32(0, false);
}

enum CryptokiKeyType {
  CKK_RSA = 0x00,
  CKK_DSA = 0x01,
  CKK_DH = 0x02,
  CKK_EC = 0x03,
  CKK_X9_42_DH = 0x04,
  CKK_KEA = 0x05,
  CKK_GENERIC_SECRET = 0x10,
  CKK_RC2 = 0x11,
  CKK_RC4 = 0x12,
  CKK_DES = 0x13,
  CKK_DES2 = 0x14,
  CKK_DES3 = 0x15,
  CKK_CAST = 0x16,
  CKK_CAST3 = 0x17,
  CKK_CAST5 = 0x18,
  CKK_CAST128 = 0x18,
  CKK_RC5 = 0x19,
  CKK_IDEA = 0x1a,
  CKK_SKIPJACK = 0x1b,
  CKK_BATON = 0x1c,
  CKK_JUNIPER = 0x1d,
  CKK_CDMF = 0x1e,
  CKK_AES = 0x1f,
  CKK_BLOWFISH = 0x20,
  CKK_TWOFISH = 0x21,
  CKK_SECURID = 0x22,
  CKK_HOTP = 0x23,
  CKK_ACTI = 0x24,
  CKK_CAMELLIA = 0x25,
  CKK_ARIA = 0x26,
}

function stringifyAttributeValue(tag: AttributeType, value: Uint8Array) {
  switch (tag) {
    case AttributeType.OBJ_ATTR_CLASS:
      return stringifyAttributeEnum(value, CryptokiObjectClass);
    case AttributeType.OBJ_ATTR_TOKEN:
    case AttributeType.OBJ_ATTR_PRIVATE:
    case AttributeType.OBJ_ATTR_TRUSTED:
    case AttributeType.OBJ_ATTR_SENSITIVE:
    case AttributeType.OBJ_ATTR_ENCRYPT:
    case AttributeType.OBJ_ATTR_DECRYPT:
    case AttributeType.OBJ_ATTR_WRAP:
    case AttributeType.OBJ_ATTR_UNWRAP:
    case AttributeType.OBJ_ATTR_SIGN:
    case AttributeType.OBJ_ATTR_VERIFY:
    case AttributeType.OBJ_ATTR_DERIVE:
    case AttributeType.OBJ_ATTR_EXTRACTABLE:
    case AttributeType.OBJ_ATTR_LOCAL:
    case AttributeType.OBJ_ATTR_NEVER_EXTRACTABLE:
    case AttributeType.OBJ_ATTR_ALWAYS_SENSITIVE:
    case AttributeType.OBJ_ATTR_WRAP_WITH_TRUSTED:
    case AttributeType.OBJ_ATTR_SPLITTABLE:
    case AttributeType.OBJ_ATTR_IS_SPLIT:
      return stringifyAttributeBoolean(value);
    case AttributeType.OBJ_ATTR_LABEL:
      return stringifyAttributeText(value);
    case AttributeType.OBJ_ATTR_KEY_TYPE:
      return stringifyAttributeEnum(value, CryptokiKeyType);
    case AttributeType.OBJ_ATTR_ID:
      return stringifyAttributeText(value);
    case AttributeType.OBJ_ATTR_MODULUS_BITS:
    case AttributeType.OBJ_ATTR_VALUE_LEN:
      return stringifyAttributeNumber(value); // TODO: Check if this is correct
    case AttributeType.OBJ_ATTR_KCV:
    case AttributeType.OBJ_ATTR_MODULUS:
    case AttributeType.OBJ_EXT_ATTR1:
    case AttributeType.OBJ_ATTR_ENCRYPT_KEY_MECHANISMS:
    case AttributeType.OBJ_ATTR_DECRYPT_KEY_MECHANISMS:
    case AttributeType.OBJ_ATTR_SIGN_KEY_MECHANISMS:
    case AttributeType.OBJ_ATTR_VERIFY_KEY_MECHANISMS:
    case AttributeType.OBJ_ATTR_WRAP_KEY_MECHANISMS:
    case AttributeType.OBJ_ATTR_UNWAP_KEY_MECHANISMS:
    case AttributeType.OBJ_ATTR_DERIVE_KEY_MECHANISMS:
    default:
      return Buffer.from(value).toString('hex');
  }
}

function stringifyAttestationFlags(flags: AttestationFlags) {
  const values: string[] = [];
  if (flags & AttestationFlags.KEY_GEN_FLAG_GET_ATTR) {
    values.push('KEY_GEN_FLAG_GET_ATTR');
  }
  if (flags & AttestationFlags.KEY_GEN_FLAG_GET_ATTEST) {
    values.push('KEY_GEN_FLAG_GET_ATTEST');
  }
  if (flags & AttestationFlags.KEY_GEN_FLAG_EXCLUDE_HEADER) {
    values.push('KEY_GEN_FLAG_EXCLUDE_HEADER');
  }

  return values.join(' | ');
}

//#endregion

program.parse(process.argv);
