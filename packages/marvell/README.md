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

This example uses the generic Marvell profile. For Google Cloud HSM, select the explicit profile described below:

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

## Evidence parsing, verification and key extraction

The concrete Marvell provider exposes independent operations so that evidence about a
symmetric key, an unsupported key algorithm or incomplete key attributes can still be
inspected and verified without extracting an attested public key:

```typescript
const provider = new MarvellAttestationProvider({ profile: "google-cloud-hsm" });
const evidence = provider.parse(attestationData);
const result = await provider.verifyEvidence({
  evidence,
  intermediateCerts: certs,
});

// Alternatively, pass raw bytes directly; parsing failures become verification results.
const fromBytes = await provider.verifyEvidence({
  evidence: attestationData,
  intermediateCerts: certs,
});

// Optional and independent: extraction can throw even when result.status is true.
// Call only when an attested public key is needed, and handle extraction errors separately.
const publicKey = provider.extractPublicKey(evidence);
```

| Method                              | Behavior                                                                                                                                           | Failure handling                                                                           |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `parse(data)`                       | Synchronously returns `MarvellAttestation` metadata, signed bytes and signature; does not extract a key                                            | Parsing errors throw                                                                       |
| `verifyEvidence({ evidence, ... })` | Accepts parsed evidence or a `BufferSource`; verifies the evidence signature and configured certificate policy without extracting the attested key | Returns `{ status: false, error }` for parsing, trust configuration or verification errors |
| `extractPublicKey(evidence)`        | Synchronously extracts the attested public key using the existing RSA/EC support                                                                   | Existing extraction errors throw, including unsupported key type or curve                  |
| `read(data)`                        | Preserves the existing `{ format, publicKey, metadata }` result; performs parsing and extraction                                                   | Its promise rejects if either operation fails                                              |
| `verify({ attestation, ... })`      | Preserves the existing format check and verifies `attestation.metadata` through the same evidence-verification path                                | Preserves the verification-result contract                                                 |

`MarvellEvidenceVerificationParams` is exported from the package entry point. It has
`evidence` instead of `attestation` and otherwise uses the same `intermediateCerts` and
`trustedCerts` options as `MarvellAttestationVerificationParams`. Input supports raw or
gzipped bytes, `ArrayBuffer` and array-buffer views. Both verification methods preserve
the selected profile, configured Crypto provider and isolated per-call trust overrides.

The shared `AttestationProvider.read()` interface and `Attestation.publicKey` remain
unchanged: `publicKey` is still required. Existing RSA/EC callers can keep using
`read()` followed by `verify()`. Use the concrete Marvell provider's evidence API when
extraction is unnecessary or unsupported; no dummy public key is required.

Parsing and extraction do not authenticate evidence. A successful `verifyEvidence()`
result confirms the signature and configured certificate policy, independently of
whether the attested key can be extracted. It does not itself match that key or other
attributes against an expected external key or resource. This change does not extend
key algorithm support or add full validation of attested key material.

## Trusted certificates

`verify({ trustedCerts })` replaces the constructor's trust anchors for that call only.
Omitting `trustedCerts`, or passing `undefined`, uses the constructor's configuration;
without custom constructor anchors, the bundled manufacturer and owner roots are used.
No anchors are merged automatically, and an unsuccessful override never falls back to
constructor or bundled roots. To combine trust configurations, explicitly supply the
complete intended set.

The **generic** profile uses a certificate array and requires at least two configured
anchors and a path to **every** anchor in the selected set. An explicit empty array or a one-certificate override returns
`{ status: false, error }`; invalid constructor configuration still throws immediately.
Yubico's trust-store policy differs: it accepts a path to any configured anchor.

```typescript
const provider = new MarvellAttestationProvider({ trustedCerts: rootsA });
const result = await provider.verify({
  attestation,
  intermediateCerts: certs,
  trustedCerts: rootsB, // Only rootsB applies to this call; rootsA remains the default.
});
```

Trust-anchor arrays are copied when the provider is constructed or verification starts.
Per-call overrides are isolated from concurrent and subsequent calls and preserve the
constructor's WebCrypto provider. The CLI's `--cert` bundle supplies untrusted signing
and intermediate certificates; it does not replace the bundled trust anchors.

## Google Cloud HSM profile

Select the profile explicitly; `new MarvellAttestationProvider()` retains generic
validation and does not infer a profile from certificate names, bundle contents or
trust overrides. The CLI's `marvell verify` command selects `google-cloud-hsm`.

```typescript
const provider = new MarvellAttestationProvider({ profile: "google-cloud-hsm" });
const result = await provider.verify({ attestation, intermediateCerts: certs });
```

The profile requires one complete set of four distinct certificate identities:

```text
manufacturerRoot -> manufacturerCard -> manufacturerPartition
ownerRoot        -> ownerCard
ownerRoot        -> ownerPartition

key(manufacturerCard)      = key(ownerCard)
key(manufacturerPartition) = key(ownerPartition)
```

Every arrow is an immediate issuer/subject match and verified certificate signature.
The partition key must also verify the evidence signature. An indirect path through
owner-card cannot replace owner-partition. Roles are established by these relationships,
not CN text, certificate ordering or SKI. When one combination fails, alternative
combinations are tried in deterministic DER order.

Keys are compared as canonical SPKI exported through the configured WebCrypto provider.
RSA PKCS#1 and EC public keys are supported for anchors and card certificates; the
evidence signer must use RSA PKCS#1 v1.5 with SHA-256. RSA-PSS restrictions are not
stripped to make keys match. Equal card/partition keys are permitted when the four
certificates are distinct. Configured anchors cannot occupy these roles, and
manufacturer and owner anchors must have independent public keys.

The default named pair is the bundled Marvell/Cavium manufacturer root and Google's
Hawksbill owner root. To use custom authorities, specify both roles explicitly:

```typescript
const provider = new MarvellAttestationProvider({
  profile: "google-cloud-hsm",
  trustedCerts: { manufacturerRoot, ownerRoot },
});

const result = await provider.verify({
  attestation,
  intermediateCerts: certs,
  trustedCerts: { manufacturerRoot: replacementManufacturer, ownerRoot: replacementOwner },
});
```

A per-call pair replaces both constructor anchors without changing the profile or
falling back. Omission or `undefined` keeps constructor defaults. Flat arrays (including
`[]`), partial pairs and `null` are rejected explicitly. Structural constructor
configuration errors throw; invalid per-call configuration returns `{ status: false,
error }`. Key errors requiring asynchronous normalization (including equivalent anchor
keys with different SPKI encodings) also return a failed verification result.
Named trust objects are snapshotted before asynchronous verification. Use the concrete
Marvell provider and its `MarvellAttestationVerificationParams` type for these overrides;
the shared provider interface retains its array-based trust parameter. The generic
profile rejects named pairs. Custom anchors bind the authorities selected by the caller.
Root rotation requires an explicit replacement of the complete named pair.

On success, `signer` is manufacturer-partition and `chain` is
`[manufacturerRoot, manufacturerCard, manufacturerPartition]`. The shared result shape
is unchanged. Missing, substituted or incorrectly signed components cannot be replaced
by duplicate copies of another role's certificate.

Input remains bounded to 64 certificates and anchors combined, and 1 MiB of combined
DER (including duplicates). Direct relation results and key normalization are cached per
call: at most 64 squared certificate pairs and one evidence check per normalized key.
There is no recursive path search in this profile. Unused certificates, duplicate DER
and copies of anchors are permitted when a complete proof exists; they do not establish
trust. This deliberately differs from the reference script's rejection of unused entries.

The guarantees cover the four certificate relationships, the two key equalities and
the signature over `signedData`. Certificate dates, CA constraints, usages, policies,
revocation, evidence freshness and matching an expected resource ID or external public
key are separate checks. This profile preserves signature-only certificate verification.

See [Google's reference verifier](https://github.com/GoogleCloudPlatform/python-docs-samples/blob/main/kms/attestations/verify_attestation_chains.py)
and [Cloud HSM attestation guidance](https://docs.cloud.google.com/kms/docs/attest-key).

## Generic certificate path verification

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

The generic path builder checks certificate signatures and explicit anchor membership.
The Google-specific card/partition guarantees belong to the explicit Google profile;
full PKIX validation remains outside both profiles.
A failed verification can omit `signer` and `chain`, including when no signing key
verifies the evidence signature.

## Links

- [Google Cloud KMS Attestation](https://cloud.google.com/kms/docs/attest-key)
- [Marvell Key attestation](https://www.marvell.com/products/security-solutions/nitrox-hs-adapters/software-key-attestation.html)

## License

This project is licensed under the MIT License.
