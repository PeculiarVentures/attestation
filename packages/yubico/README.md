<h1 align="center">
  @peculiar/attestation-yubico
</h1>

<div align="center">

![NPM License](https://img.shields.io/npm/l/@peculiar/attestation-yubico)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/PeculiarVentures/attestation/publish.yml?branch=main&label=publish)
[![npm version](https://img.shields.io/npm/v/@peculiar/attestation-yubico.svg)](https://www.npmjs.com/package/@peculiar/attestation-yubico)
![Coveralls](https://img.shields.io/coverallsCoverage/github/PeculiarVentures/attestation)
[![npm downloads](https://img.shields.io/npm/dm/@peculiar/attestation-yubico.svg)](https://www.npmjs.com/package/@peculiar/attestation-yubico)

</div>

A library providing tools to verify PIV attestation files from Yubico, including support for certificate chain validation and attestation data extraction.

## Installation

> ⚠️ This package depends on `@peculiar/x509`, which requires Reflect metadata support at runtime.
> Import `@abraham/reflection` (or another compatible polyfill) once at application startup before any attestation-related code.
>
> ```ts
> import "@abraham/reflection";
> ```

To install the library, use npm:

```sh
npm install @peculiar/attestation-yubico
```

## Breaking Changes In v3

v3 is ESM-only and requires Node.js `^20.19.0 || >=22.12.0` (2.x had no `engines` field). CommonJS code can still `require("@peculiar/attestation-yubico")` on these versions; Node.js 22.0–22.11 can't. The public API is unchanged, apart from the new `getDefaultRootCerts()`. See the [full notes](https://github.com/PeculiarVentures/attestation#breaking-changes-in-v3).

- **TypeScript compiling to CommonJS:** use `"module": "node20"` or `"nodenext"` (`node16` fails with TS1479). ESM and bundler setups need no changes.
- **Jest in CommonJS mode:** switch to ESM mode or Vitest, or configure an ESM-to-CommonJS transformer and make sure `transformIgnorePatterns` doesn't exclude the `@peculiar/*` packages, `asn1js` and `tsyringe`.
- **Deep imports** (`@peculiar/attestation-yubico/build/...`) are blocked by `exports`; import from `@peculiar/attestation-yubico`.
- **Peer dependency:** `@peculiar/x509` (`^3.1.0`) is a peer instead of a dependency, so certificates you pass in and get back come from your app's copy. npm installs peers automatically.

## Usage

This example demonstrates how to verify a PIV attestation from a Yubico token:

```typescript
import { PivTokenManager, PivAttestationProvider } from "@peculiar/attestation-yubico";

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
  intermediateCerts: [slot.caCertificate],
});

console.log(result);

// Close the token manager
tokenManager.close();
```

## Trusted certificates

When `trustedCerts` is omitted, the provider trusts both the legacy Yubico PIV Root CA Serial 263751 and Yubico Attestation Root 1, used by firmware 5.7.4 and later.
The roots and the required production PIV intermediate CA certificates are bundled with the package, so verification works offline. Supply the device's attestation CA certificate from slot `f9` through `intermediateCerts`, as shown above.
Bundled intermediate certificates are used only to build chains; they are never implicitly trusted. Issuers are selected using certificate relationships and signature verification, without firmware detection.

The bundled certificates come from Yubico's official [PIV attestation documentation](https://developers.yubico.com/PIV/Introduction/PIV_attestation.html):

- [Legacy PIV root](https://developers.yubico.com/PKI/yubico-piv-ca-1.pem)
- [Attestation Root 1](https://developers.yubico.com/PKI/yubico-ca-1.pem)
- [Intermediate CA bundle](https://developers.yubico.com/PKI/yubico-intermediate.pem) (Attestation Intermediate A 1 / B 1 and PIV Attestation A 1 / B 1 / B2 1)

Use `getDefaultRootCerts(): X509Certificate[]` to retrieve all built-in trusted roots. To extend the default trust store with custom roots:

```typescript
const result = await provider.verify({
  attestation: attest,
  intermediateCerts: [slot.caCertificate],
  trustedCerts: [...provider.getDefaultRootCerts(), ...customRootCerts],
});
```

Providing `trustedCerts` replaces the default trust store entirely. To trust only your own roots:

```typescript
const result = await provider.verify({
  attestation: attest,
  intermediateCerts: [slot.caCertificate],
  trustedCerts: customRootCerts,
});
```

An empty `trustedCerts: []` trusts no certificates. `getDefaultRootCert()` remains available and returns only the legacy root; it is deprecated in favor of `getDefaultRootCerts()`.
Explicitly trusted certificates can also be non-self-signed trust anchors, such as a pinned device certificate from slot `f9`. The returned verified chain ends at the first trusted certificate.

## License

This project is licensed under the MIT License.
