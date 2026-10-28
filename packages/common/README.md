# @peculiar/attestation-common

A common module providing tools and interfaces for verifying HSM attestation files from various HSMs, including support for certificate chain validation and attestation data extraction.

## Installation

> ⚠️ This package depends on `@peculiar/x509`, which requires Reflect metadata support at runtime.
> Import `@abraham/reflection` (or another compatible polyfill) once at application startup before any attestation-related code.
>
> ```ts
> import "@abraham/reflection";
> ```

To install the library, use npm:

```sh
npm install @peculiar/attestation-common
```

## Usage

This example demonstrates how to use the common attestation interfaces and types:

```typescript
import { X509Certificate, PublicKey } from "@peculiar/x509";
import { Attestation, AttestationVerificationParams, AttestationVerificationResult, AttestationProvider } from "@peculiar/attestation-common";

// Example implementation of an AttestationProvider
class ExampleAttestationProvider implements AttestationProvider {
  format = "example";

  async read(data: BufferSource): Promise<Attestation> {
    // Implement the logic to read attestation data
    return {
      format: this.format,
      publicKey: new PublicKey /* public key data */(),
      metadata: {/* metadata */},
    };
  }

  async verify(params: AttestationVerificationParams): Promise<AttestationVerificationResult> {
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
const attestationData = new Uint8Array([/* attestation data bytes */]);
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

## Verification trust configuration

`intermediateCerts` supplies untrusted certificates for path construction.
`trustedCerts`, when supplied, replaces the provider's default trust configuration for
that verification call. Omission or `undefined` keeps the defaults; an explicit empty
array does not fall back to them. Provider-specific rules still apply: generic Marvell requires
paths to every configured root and at least two anchors, while Yubico accepts a path
to any configured anchor and treats an empty set as trusting no certificates.
The concrete Marvell provider additionally supports a Google Cloud HSM profile with
named manufacturer/owner anchors through its format-specific verification parameters.
That profile explicitly rejects flat trust arrays; the shared interface stays unchanged.

The shared `AttestationProvider.read()` contract still returns an attestation with a
required `publicKey`. The concrete Marvell provider additionally exposes `parse()`,
`verifyEvidence()` and `extractPublicKey()` so that parsing and verification need not
extract the attested key. Use that format-specific evidence API for symmetric or
unsupported attested keys; existing `read()` and `verify()` callers remain compatible.

Marvell verification additionally returns format-specific `signature` and `trust`
checks with `passed`, `failed` or `not-evaluated` states and reasons for non-passing
checks. Its result remains assignable to the shared result type. Overall success
requires both checks to pass for the same signing key; the shared interface and
Yubico result are unchanged. Use the concrete Marvell provider for these typed fields.

## License

This project is licensed under the MIT License.
