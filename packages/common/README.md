# @peculiar/attestation-common

A common module providing tools and interfaces for verifying HSM attestation files from various HSMs, including support for certificate chain validation and attestation data extraction.

## Installation

To install the library, use npm:

```sh
npm install @peculiar/attestation-common
```

## Usage

This example demonstrates how to use the common attestation interfaces and types:

```typescript
import { X509Certificate, PublicKey } from "@peculiar/x509";
import {
  Attestation,
  AttestationVerificationParams,
  AttestationVerificationResult,
  AttestationProvider,
} from "@peculiar/attestation-common";

// Example implementation of an AttestationProvider
class ExampleAttestationProvider implements AttestationProvider {
  format = "example";

  async read(data: BufferSource): Promise<Attestation> {
    // Implement the logic to read attestation data
    return {
      format: this.format,
      publicKey: new PublicKey(/* public key data */),
      metadata: {
        /* metadata */
      },
    };
  }

  async verify(
    params: AttestationVerificationParams
  ): Promise<AttestationVerificationResult> {
    // Implement the logic to verify attestation data
    return {
      status: true,
      chain: params.intermediateCerts,
      signer: params.intermediateCerts[0],
    };
  }
}

// Example usage
const provider = new ExampleAttestationProvider();

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

## License

This project is licensed under the MIT License.
