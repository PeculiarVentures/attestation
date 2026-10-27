# @peculiar/attestation-marvell

A library providing tools to verify HSM attestation files from various HSMs that support Marvell attestation, including support for certificate chain validation and attestation data extraction.

## Installation

> ⚠️ This package depends on `@peculiar/x509`, which requires Reflect metadata support at runtime.
> Import `@abraham/reflection` (or another compatible polyfill) once at application startup before any attestation-related code.
>
> ```ts
> import "@abraham/reflection";
> ```

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

## Certificate path verification

The validator identifies candidate signing keys using the evidence signature, then uses
`X509ChainBuilder.buildToAnchor()` to confirm a path to **every** configured root.
Certificates with the same signing key may differ between paths. The returned `chain`
remains in root-to-signer order and corresponds to the first configured root.
Duplicate certificates and roots in the input bundle are supported; self-issued
certificates are not discarded. The selected DER path is independent of bundle order.

Validation accepts at most 64 input certificates and configured roots combined, with
at most 1 MiB of combined DER data (including duplicates). Each path search permits
16 certificates, including its signer and anchor, and 10,000 considered edges. A
validation call permits at most 128 path searches across all candidates and roots.
Resource exhaustion returns `status: false`; x509's `LIMIT_EXCEEDED` error is retained
when no other candidate supplies the required path after a depth or step limit.
Evidence parsing and decompression are outside these certificate-search limits.

The path builder checks certificate signatures and explicit anchor membership. These
checks do not add full PKIX validation or the Google-specific card/partition policy.
A failed verification can omit `signer` and `chain`, including when no signing key
verifies the evidence signature.

### Development with the unreleased x509 API

This change requires `buildToAnchor()` from
[PeculiarVentures/x509#167](https://github.com/PeculiarVentures/x509/pull/167).
Until that API is published, use a built local checkout of x509 for development.
Package manifests and the lockfile are intentionally unchanged; a clean installation
of the currently published dependency does not provide this API yet. Publishing this
package requires a follow-up dependency update to a release containing it.

## Links

- [Google Cloud KMS Attestation](https://cloud.google.com/kms/docs/attest-key)
- [Marvell Key attestation](https://www.marvell.com/products/security-solutions/nitrox-hs-adapters/software-key-attestation.html)

## License

This project is licensed under the MIT License.
