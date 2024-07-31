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
  CryptokiKeyType,
  CryptokiObjectClass,
  Attributes,
  AttributeValue,
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
    '-m, --mfr [file]',
    'The file containing the manufacturer root certificate',
  )
  .option(
    '-o, --owner [file]',
    'The file containing the owner root certificate',
  )
  .option('--info', 'Output information about the attestation')
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

        const validator = new KmsAttestationValidator(validatorParams);
        const result = await validator.validate(attestationData, certificates);

        if (info) {
          printAttestation(attestationData);
          // print info about signer
          const signer = result.signer;
          console.log('Signer Certificate:');
          console.log(`  Subject: ${signer.subject}`);
          console.log(`  Issuer: ${signer.issuer}`);
          console.log(`  Serial Number: ${signer.serialNumber}`);
          console.log(`  Valid From: ${signer.notAfter}`);
          console.log(`  Valid To: ${signer.notBefore}`);

          // print info about certificate chain
          const chain = result.chain.slice(1);
          let tab = TAB;
          console.log('Certificate Chain:');
          for (const cert of chain) {
            console.log(`${tab}Certificate: ${cert.subject}`);
            tab += TAB;
          }
        }

        console.log('Attestation:', result.isValid ? 'PASSED' : 'FAILED');

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

function printAttributes(attributes: Attributes, tab = '') {
  console.log(`${tab}Attributes:`);
  for (const [key, value] of Object.entries(attributes)) {
    console.log(`${tab}${TAB}${key}: ${stringifyAttributeValue(value)}`);
  }
}

function stringifyAttributeValue(value: AttributeValue): string {
  if (value instanceof Uint8Array) {
    return Buffer.from(value).toString('hex');
  } else {
    return `${value}`;
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
