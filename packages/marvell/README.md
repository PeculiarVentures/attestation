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

## Signature and certificate-trust results

Both `verify()` and `verifyEvidence()` return `MarvellAttestationVerificationResult`,
a compatible extension of the shared result. Inspect `signature` and `trust` directly;
neither the presence of a certificate nor a successful key extraction establishes trust.

```typescript
const result = await provider.verifyEvidence({ evidence, intermediateCerts: certs });
console.log(result.signature.status, result.trust.status);
if (result.signature.status !== "passed") {
  console.log(result.signature.reason, result.signature.error.message);
}
if (result.trust.status !== "passed") {
  console.log(result.trust.reason, result.trust.error.message);
}
if (result.status) {
  // Both checks passed for the same signing-key group.
  console.log(result.signer.subject);
}
```

Each check has one of these states:

| State           | Meaning                                                                                |
| --------------- | -------------------------------------------------------------------------------------- |
| `passed`        | The signature verified, or the configured certificate policy was proven, respectively  |
| `failed`        | The check conclusively rejected its relevant candidates; includes `reason` and `error` |
| `not-evaluated` | The check could not establish a conclusive result; includes `reason` and `error`       |

For example, a valid signature with no trusted path gives signature `passed`, trust
`failed`, overall `status: false`. A corrupted signature with a complete certificate
proof gives signature `failed`, trust `passed`, overall `status: false`. Trust alone
does not authenticate the evidence. Overall success requires both checks to pass for
the same key and preserves the existing root-to-signer `chain` order.

Signature mismatch means that the relevant supplied, compatible signing keys were
actually checked and rejected. A missing signer is not a mismatch. Known non-RSA keys
cannot sign the fixed RSA evidence format; they yield unsupported-algorithm diagnostics
when no compatible signing key is available. Multiple mismatch-only key groups remain
a conclusive failure; a mixture of plausible RSA mismatches and uncheckable candidates
is inconclusive. Same-key certificates and DER duplicates do not themselves establish
another signer identity.

The relevant key set is chosen without combining independent proofs from different
keys. If any signature verifies, only signature-passing key groups determine trust.
Otherwise, proven policy-approved groups determine the signature result when available;
an incomplete search retains uncertain candidates. This prevents a valid, untrusted
key from borrowing another key's trusted certificate proof. Generic validation keeps
its existing RSA-PSS export behavior; the Google profile retains its stricter SPKI
algorithm restrictions.

Non-passing checks use these exported `MarvellVerificationReason` values:

| Reason                        | Meaning                                                                      |
| ----------------------------- | ---------------------------------------------------------------------------- |
| `invalid-signature`           | Relevant eligible keys conclusively rejected the signature                   |
| `untrusted-certificates`      | No required certificate proof exists for the relevant candidates             |
| `missing-signer`              | No candidate signing key was supplied, including anchor-only pools           |
| `ambiguous-signer`            | Plausible candidate keys have inconclusive or mixed verification outcomes    |
| `malformed-evidence`          | Raw evidence could not be parsed or parsed cryptographic buffers are invalid |
| `unsupported-algorithm`       | The signing key or configured cryptographic operation is unsupported         |
| `invalid-trust-configuration` | The per-call trust configuration was rejected                                |
| `resource-limit`              | Input bounds or certificate-search limits prevented evaluation               |
| `verification-error`          | A cryptographic operation or certificate check could not complete            |
| `invalid-format`              | Legacy `verify()` received another attestation format                        |

Limits and runtime errors are not definitive trust rejection. A signature already
verified remains `passed` when its certificate search reaches a limit; the original
x509 limit error remains available. Diagnostic searches reuse the same request budget
and run after acceptance searches, so they cannot consume a successful search's budget.
A generic candidate's incomplete chain search no longer aborts all other signing-key
groups: later groups can still supply a valid signature and complete proof within the
same shared 128-attempt budget.

Google profile diagnostics are deliberately conservative across the certificate bundle.
If an attempted certificate edge throws, every group without a proven complete policy
receives `not-evaluated`, even when the exception came from an unrelated candidate.
The reason is `verification-error`, or `unsupported-algorithm` when reported by Crypto.
Its top-level error can therefore be that exception instead of the usual card/partition
message. An ordinary false certificate-signature result does
not trigger this behavior, and a complete same-key proof still permits acceptance.

Failed results omit the legacy `signer` and `chain`. When one relevant key group is
identified, optional `candidate.certificates` provides its DER-distinct certificates.
A `candidate.chain`, if present, is a policy-proven path for that candidate, even if its
evidence signature failed. These diagnostics confer no signature validity or overall
acceptance; they are omitted when no unique relevant key group can be identified.
The top-level `error` remains available, with existing messages retained where applicable.

The shared result type and Yubico behavior are unchanged. Call through the concrete
Marvell provider to access the additional typed checks. Trust means the selected
profile's certificate-signature policy; the PKIX, freshness and expected-key exclusions
described below still apply.

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
A failed verification omits the legacy `signer` and `chain`; use the explicit checks
and optional candidate diagnostics described above.

## Links

- [Google Cloud KMS Attestation](https://cloud.google.com/kms/docs/attest-key)
- [Marvell Key attestation](https://www.marvell.com/products/security-solutions/nitrox-hs-adapters/software-key-attestation.html)

## License

This project is licensed under the MIT License.
