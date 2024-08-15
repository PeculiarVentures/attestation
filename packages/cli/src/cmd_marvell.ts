import fs from 'node:fs';
import x509 from '@peculiar/x509';
import {
  MarvellAttestation,
  ResponseHeader,
  MarvellAttestationData,
  ObjectAttributes,
  Attributes,
  AttributeValue,
  MarvellAttestationFlags,
  MarvellAttestationProvider,
  MarvellAttestationType,
} from '@peculiar/attestation-marvell';
import { program } from './program';
import {
  printCertificate,
  printCertificateShort,
  printPublicKey,
  TAB,
} from './common';

export function printAttestation(attestation: MarvellAttestation, tab = '') {
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

function printAttestationData(attestation: MarvellAttestationData, tab = '') {
  console.log(`${tab}Key Attestation Data:`);
  console.log(`${tab}${TAB}Version: v${attestation.info.objectVersion}`);
  console.log(
    `${tab}${TAB}Flags: ${stringifyAttestationFlags(
      attestation.info.requestFlags,
    )}`,
  );

  printObject(attestation.firstKey, 'First Key', tab + TAB);
  if (attestation.secondKey) {
    printObject(attestation.secondKey, 'Second Key', tab + TAB);
  }
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
    return `0x${Buffer.from(value).toString('hex')}`;
  } else {
    return `${value}`;
  }
}

function stringifyAttestationFlags(flags: MarvellAttestationFlags) {
  const values: string[] = [];
  if (flags & MarvellAttestationFlags.KEY_GEN_FLAG_GET_ATTR) {
    values.push('KEY_GEN_FLAG_GET_ATTR');
  }
  if (flags & MarvellAttestationFlags.KEY_GEN_FLAG_GET_ATTEST) {
    values.push('KEY_GEN_FLAG_GET_ATTEST');
  }
  if (flags & MarvellAttestationFlags.KEY_GEN_FLAG_EXCLUDE_HEADER) {
    values.push('KEY_GEN_FLAG_EXCLUDE_HEADER');
  }

  return values.join(' | ');
}

async function printAttestationDetails(
  attestation: MarvellAttestationType,
  tab = '',
) {
  printAttestation(attestation.metadata, tab);
  await printPublicKey(attestation.publicKey, tab);
}

async function detailAttestation(file: string) {
  if (!fs.existsSync(file)) {
    console.error(`File not found: ${file}`);
    process.exit(1);
  }

  const data = fs.readFileSync(file);
  const marvellAttestation = new MarvellAttestationProvider();
  const attestation = await marvellAttestation.read(data);

  await printAttestationDetails(attestation, '');
}

const marvellCommand = program
  .command('marvell')
  .description('Marvell attestation commands');

interface MarvellInfoOptions {}

marvellCommand
  .command('info')
  .description('Detail the attestation')
  .argument('<attestation-file>', 'The attestation file path')
  .action(async (attestationFile: string, options: MarvellInfoOptions) => {
    await detailAttestation(attestationFile);
  });

interface MarvellVerifyOptions {
  cert: string;
}

marvellCommand
  .command('verify')
  .description('Verify the attestation')
  .argument('<attestation-file>', 'The attestation file path')
  .requiredOption('-c, --cert <file>', 'The certificate file path')
  .action(async (attestationFile: string, options: MarvellVerifyOptions) => {
    if (!fs.existsSync(attestationFile)) {
      console.error(`Attestation file not found: ${attestationFile}`);
      process.exit(1);
    }

    const certFile = options.cert;
    if (!fs.existsSync(certFile)) {
      console.error(`Certificate file not found: ${certFile}`);
      process.exit(1);
    }

    const attestationData = fs.readFileSync(attestationFile);
    const certData = fs.readFileSync(certFile);
    const certBlobs = x509.PemConverter.decode(certData.toString());
    const certs = certBlobs.map((blob) => new x509.X509Certificate(blob));

    const marvellAttestation = new MarvellAttestationProvider();
    const attestation = await marvellAttestation.read(attestationData);

    const result = await marvellAttestation.verify({
      attestation,
      intermediateCerts: certs,
      trustedCerts: certs,
    });

    const key = attestation.publicKey;
    await printPublicKey(key);
    console.log();

    if (result.chain) {
      console.log('Signing certificate chain:');
      let tab = '';
      for (const cert of result.chain) {
        await printCertificateShort(cert, '', tab);
        console.log();
        tab += TAB;
      }
    }

    console.log('Attestation verification:');
    if (result.status) {
      console.log(`${TAB}Status: PASSED`);
    } else {
      console.error(`${TAB}Status: FAILED`);
      console.error(`${TAB}Error: ${result.error.message}`);
      process.exit(1);
    }
  });

interface MarvellCertsOptions {
  details: boolean;
}

marvellCommand
  .command('certs')
  .description('Detail the certificate file')
  .argument('<cert-file>', 'The certificate file path')
  .option('-d, --details', 'Show detailed certificate information', false)
  .action(async (certFile: string, options: MarvellCertsOptions) => {
    if (!fs.existsSync(certFile)) {
      console.error(`File not found: ${certFile}`);
      process.exit(1);
    }

    const data = fs.readFileSync(certFile);
    const certBlobs = x509.PemConverter.decode(data.toString());
    const certs = certBlobs.map((blob) => new x509.X509Certificate(blob));

    for (const cert of certs) {
      if (!options.details) {
        await printCertificateShort(cert);
      } else {
        await printCertificate(cert);
      }
      console.log();
    }
  });

interface MarvellKeyOptions {
  key: string;
  outputFile?: string;
  outputFormat?: string;
}

marvellCommand
  .command('key')
  .description(
    'Export the public key and optionally compare with a source key or save to a file',
  )
  .argument('<attestation-file>', 'The attestation file path')
  .option(
    '-k, --key <key>',
    'The source key to compare. Can be a CSR, SPKI, or X.509 certificate file in PEM or DER format',
  )
  .option('-o, --output [file]', 'The output file to save the public key')
  .option('-f, --format [format]', 'The output format (pem, der)', 'pem')
  .action(async (attestationFile: string, options: MarvellKeyOptions) => {
    // Read the attestation file
    if (!fs.existsSync(attestationFile)) {
      console.error(`Attestation file not found: ${attestationFile}`);
      process.exit(1);
    }

    const attestationData = fs.readFileSync(attestationFile);
    const marvellAttestation = new MarvellAttestationProvider();
    const attestation = await marvellAttestation.read(attestationData);

    // Extract the public key
    const publicKey = attestation.publicKey;
    await printPublicKey(publicKey);

    if (options.outputFile) {
      if (options.outputFormat === 'pem') {
        fs.writeFileSync(options.outputFile, publicKey.toString('pem'), {
          flag: 'w+',
        });
      } else if (options.outputFormat === 'der') {
        fs.writeFileSync(options.outputFile, Buffer.from(publicKey.rawData), {
          flag: 'w+',
        });
      } else {
        console.error(`Invalid output format: ${options.outputFormat}`);
        process.exit(1);
      }
    }

    // Compare the public key
    if (options.key) {
      if (!fs.existsSync(options.key)) {
        console.error(`Key file not found: ${options.key}`);
        process.exit(1);
      }

      const keyData = fs.readFileSync(options.key);
      let keyId: ArrayBuffer;
      try {
        // Try to parse the key as a public key
        const key = new x509.PublicKey(keyData);
        keyId = await key.getKeyIdentifier();
      } catch {
        try {
          // Try to parse the key as an X.509 certificate
          const cert = new x509.X509Certificate(keyData);
          keyId = await cert.publicKey.getKeyIdentifier();
        } catch {
          try {
            // Try to parse the key as a CSR
            const csr = new x509.Pkcs10CertificateRequest(keyData);
            keyId = await csr.publicKey.getKeyIdentifier();
          } catch {
            console.error(`Invalid key format: ${options.key}`);
            process.exit(1);
          }
        }
      }
      const attestationKeyId = await publicKey.getKeyIdentifier();
      console.log();
      console.log('Matching public key identifiers:');
      if (
        Buffer.compare(Buffer.from(keyId), Buffer.from(attestationKeyId)) === 0
      ) {
        console.log(`${TAB}Status: PASSED`);
      } else {
        console.error(`${TAB}Status: FAILED`);
        process.exit(1);
      }
    }
  });
