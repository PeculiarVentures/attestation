# @peculiar/attestation-yubico

A library providing tools to verify PIV attestation files from Yubico, including support for certificate chain validation and attestation data extraction.

## Installation

To install the library, use npm:

```sh
npm install @peculiar/attestation-yubico
```

## Usage

This example demonstrates how to verify a PIV attestation from a Yubico token:

```typescript
import {
  PivTokenManager,
  PivAttestationProvider,
} from "@peculiar/attestation-yubico";

// Initialize the PivTokenManager
const tokenManager = new PivTokenManager("/path/to/token");

// Retrieve slots information
const slots = tokenManager.getSlots();
console.log(slots);

// Assuming the first slot is used
const slot = slots[0];

// Check if the slot has a CA certificate
if (!slot.caCertificate) {
  console.error("Token doesn't support the attestation.");
  tokenManager.close();
  return;
}

// Use specified attestation
const attestation = slot.attestations[0];

// Initialize the PivAttestationProvider
const provider = new PivAttestationProvider();
const attest = await provider.read(attestation.certificate.rawData);

// Verify the attestation using the CA certificate from the slot
const result = await provider.verify({
  attestation: attest,
  trustedCerts: [provider.getDefaultRootCert()],
  intermediateCerts: [slot.caCertificate],
});

console.log(result);

// Close the token manager
tokenManager.close();
```

## License

This project is licensed under the MIT License.
