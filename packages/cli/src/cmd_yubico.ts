import fs from 'node:fs';
import os from 'node:os';
import x509 from '@peculiar/x509';
import {
  SlotInfo,
  PivTokenManager,
  PivTokenAttestation,
  PivAttestationProvider,
} from '@peculiar/attestation-yubico';
import { program } from './program';
import { printCertificateShort, printPublicKey, TAB } from './common';

interface PivCommonOptions {
  slot: string;
  attestId: string;
  path: string;
}

interface Option {
  flag: string;
  description: string;
  defaultValue?: string;
}

const defaultPath = (() => {
  switch (os.platform()) {
    case 'win32':
      return `${process.env['PROGRAMFILES']}\\Yubico\\Yubico PIV Tool\\bin\\libykcs11.dll`;
    case 'darwin':
      return '/usr/local/lib/libykcs11.dylib';
    case 'linux':
      return '/usr/local/lib/libykcs11.so';
    default:
      return '/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so';
  }
})();

const options: Record<string, Option> = {
  slot: {
    flag: '-s, --slot [index]',
    description: 'The slot index to use',
  },
  attestId: {
    flag: '-a, --attest-id [id]',
    description: 'The attestation ID to verify',
  },
  path: {
    flag: '-p, --path [path]',
    description: 'The path to the PIV token',
    defaultValue: defaultPath,
  },
};

function printSlotDetails(slot: SlotInfo, tab = '') {
  console.log(`${tab}Slot: ${slot.slotDescription}`);
  console.log(`${tab}Token: ${slot.tokenLabel}`);
  console.log(`${tab}Serial: ${slot.tokenSerialNumber}`);
  console.log(
    `${tab}Supports Attestation: ${slot.caCertificate ? 'Yes' : 'No'}`,
  );
}

async function printAttestation(attestation: PivTokenAttestation, tab = '') {
  console.log(`${tab}Attestation ID: ${attestation.id}`);
  console.log(`${tab}Label: ${attestation.label}`);
  await printPublicKey(attestation.certificate.publicKey, tab);
}

async function printSlotInfo(slot: SlotInfo, attestationId?: string, tab = '') {
  printSlotDetails(slot, tab);
  if (slot.caCertificate) {
    const attestations = attestationId
      ? slot.attestations.filter((a) => a.id === attestationId)
      : slot.attestations;
    console.log();
    if (attestationId && attestations.length === 0) {
      console.error(`Error: Attestation ID ${attestationId} not found.`);
      process.exit(1);
    }
    console.log(`${tab}Attestations:`);
    for (const attestation of attestations) {
      await printAttestation(attestation, `${tab}${TAB}`);
      console.log();
    }
  }
}

const pivCommand = program
  .command('yubico')
  .description('Yubico attestation commands');

type PivInfoOptions = PivCommonOptions;

function getSlotIndex(options: PivCommonOptions): number {
  if (!options.slot) {
    console.error('Slot index is required.');
    process.exit(1);
  }
  const index = parseInt(options.slot, 10);
  if (isNaN(index)) {
    console.error('Invalid slot index.');
    process.exit(1);
  }
  return index;
}

pivCommand
  .command('info')
  .description('Detail the attestation')
  .option(
    options.path.flag,
    options.path.description,
    options.path.defaultValue,
  )
  .option(options.slot.flag, options.slot.description)
  .option(options.attestId.flag, options.attestId.description)
  .action(async (options: PivInfoOptions) => {
    const token = new PivTokenManager(options.path);
    try {
      if (options.slot) {
        const slotId = getSlotIndex(options);
        const slot = token.getSlot(slotId);
        if (!slot) {
          console.error(`Error: Slot ${slotId} not found.`);
          process.exit(1);
        }
        await printSlotInfo(slot, options.attestId);
      } else {
        const slots = token.getSlots();
        for (const slot of slots) {
          await printSlotInfo(slot, options.attestId);
        }
      }
    } finally {
      token.close();
    }
  });

type PivVerifyOptions = PivCommonOptions;

pivCommand
  .command('verify')
  .description('Verify the attestation')
  .option(
    options.path.flag,
    options.path.description,
    options.path.defaultValue,
  )
  .requiredOption(options.slot.flag, options.slot.description)
  .requiredOption(options.attestId.flag, options.attestId.description)
  .action(async (options: PivVerifyOptions) => {
    const token = new PivTokenManager(options.path);
    try {
      const slotId = getSlotIndex(options);
      const slot = token.getSlot(slotId);
      if (!slot) {
        console.error(`Error: Slot ${slotId} not found.`);
        process.exit(1);
      }
      if (!slot.caCertificate) {
        console.error('Error: Attestation is not supported in this slot.');
        process.exit(1);
      }
      const attestation = slot.attestations.find(
        (a) => a.id === options.attestId,
      );
      if (!attestation) {
        console.error(`Error: Attestation ID ${options.attestId} not found.`);
        process.exit(1);
      }

      const provider = new PivAttestationProvider();
      const attest = await provider.read(attestation.certificate.rawData);
      const result = await provider.verify({
        attestation: attest,
        intermediateCerts: [slot.caCertificate],
      });

      await printSlotInfo(slot, options.attestId);

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
      }
    } finally {
      token.close();
    }
  });

interface PivKeyOptions extends PivCommonOptions {
  key?: string;
  output?: string;
  format?: string;
}

pivCommand
  .command('key')
  .description(
    'Export the public key and optionally compare with a source key or save to a file',
  )
  .option(
    options.path.flag,
    options.path.description,
    options.path.defaultValue,
  )
  .requiredOption(options.slot.flag, options.slot.description)
  .requiredOption(options.attestId.flag, options.attestId.description)
  .option(
    '-k, --key <key>',
    'The source key to compare. Can be a CSR, SPKI, or X.509 certificate file in PEM or DER format',
  )
  .option('-o, --output [file]', 'The output file to save the public key')
  .option('-f, --format [format]', 'The output format (pem, der)', 'pem')
  .action(async (options: PivKeyOptions) => {
    const token = new PivTokenManager(options.path);
    try {
      const slotId = getSlotIndex(options);
      const slot = token.getSlot(slotId);
      if (!slot) {
        console.error(`Error: Slot ${slotId} not found.`);
        process.exit(1);
      }
      if (!slot.caCertificate) {
        console.error('Error: Attestation is not supported in this slot.');
        process.exit(1);
      }
      const attestation = slot.attestations.find(
        (a) => a.id === options.attestId,
      );
      if (!attestation) {
        console.error(`Error: Attestation ID ${options.attestId} not found.`);
        process.exit(1);
      }

      await printSlotInfo(slot, options.attestId);
      console.log();

      if (options.output) {
        if (!options.format || !['pem', 'der'].includes(options.format)) {
          console.error('Invalid output format.');
          process.exit(1);
        }

        const publicKey = attestation.certificate.publicKey;
        if (options.format === 'pem') {
          fs.writeFileSync(options.output, publicKey.toString('pem'), {
            flag: 'w+',
          });
        } else {
          fs.writeFileSync(options.output, Buffer.from(publicKey.rawData), {
            flag: 'w+',
          });
        }

        console.log(`Public key saved to: ${options.output}`);
      }

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
        const attestationKeyId =
          await attestation.certificate.publicKey.getKeyIdentifier();
        console.log('Matching public key identifiers:');
        if (
          Buffer.compare(Buffer.from(keyId), Buffer.from(attestationKeyId)) ===
          0
        ) {
          console.log(`${TAB}Status: PASSED`);
        } else {
          console.error(`${TAB}Status: FAILED`);
          process.exit(1);
        }
      }
    } finally {
      token.close();
    }
  });
