# @peculiar/attestation-marvell

A library providing tools to verify HSM attestation files from various HSMs that support Marvell attestation, including support for certificate chain validation and attestation data extraction.

## Installation

To install the library, use npm:

```sh
npm install @peculiar/attestation-marvell
```

## Usage

This example demonstrates how to verify an HSM attestation:

```typescript
import { MarvellAttestationProvider } from "@peculiar/attestation-marvell";
import { x509 } from "@peculiar/x509";

// Initialize the MarvellAttestationProvider
const provider = new MarvellAttestationProvider();

// Example attestation data and certificate chain data
const attestationData = new Uint8Array([
  /* attestation data bytes */
]);
const certChainPem = `-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7V1...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7V1...
-----END CERTIFICATE-----`;

// Read the attestation data
const attestation = await provider.read(attestationData);

// Decode the certificate chain
const certBlobs = x509.PemConverter.decode(certChainPem);
const certs = certBlobs.map((blob) => new x509.X509Certificate(blob));

// Verify the attestation using the provided certificate chain
const result = await provider.verify({
  attestation,
  intermediateCerts: certs,
});

console.log(result);
```

## Links

- [Google Cloud KMS Attestation](https://cloud.google.com/kms/docs/attest-key)
- [Marvell Key attestation](https://www.marvell.com/products/security-solutions/nitrox-hs-adapters/software-key-attestation.html)

## License

This project is licensed under the MIT License.
