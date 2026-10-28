<h1 align="center">
  attestation
</h1>

<div align="center">

![GitHub License](https://img.shields.io/github/license/PeculiarVentures/attestation)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/PeculiarVentures/attestation/publish.yml?branch=main&label=publish)
![Coveralls](https://img.shields.io/coverallsCoverage/github/PeculiarVentures/attestation)

</div>

Libraries and a CLI for verifying HSM and token attestation data, including certificate chain validation and attestation data extraction.

## Packages

| Package                                                       | Description                                                                                  |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| [`@peculiar/attestation-common`](packages/common/README.md)   | Shared interfaces and result types for attestation providers                                 |
| [`@peculiar/attestation-marvell`](packages/marvell/README.md) | Marvell (Cavium) HSM key attestation, including the Google Cloud HSM profile                 |
| [`@peculiar/attestation-yubico`](packages/yubico/README.md)   | Yubico PIV attestation, with a PKCS#11 token manager for reading slots                       |
| [`@peculiar/attestation-cli`](packages/cli/README.md)         | The `attest` command for inspecting and verifying attestation files, certificates and tokens |

## Installation

```sh
npm install @peculiar/attestation-marvell
npm install @peculiar/attestation-yubico
npm install -g @peculiar/attestation-cli
```

`@peculiar/x509` uses Reflect metadata, so import a polyfill such as `@abraham/reflection` (or `reflect-metadata`) once, before any attestation code. The CLI already does this.

```ts
import "@abraham/reflection";
import { MarvellAttestationProvider } from "@peculiar/attestation-marvell";
```

## Breaking Changes In v3

v3 is ESM-only and requires Node.js `^20.19.0 || >=22.12.0` (2.x had no `engines` field). CommonJS code can still `require()` the libraries on these versions; Node.js 22.0–22.11 can't (`ERR_REQUIRE_ESM`). The public API is unchanged; v3 only adds to it (the Marvell evidence API and Google Cloud HSM profile, Yubico's `getDefaultRootCerts()`).

- **One ESM build per package:** `build/cjs`, `build/esm` and `build/types` are replaced by `build/*.js` with `.d.ts` files next to them. Deep imports (`@peculiar/attestation-marvell/build/cjs/...`) are blocked by `exports`; import from the package name.
- **TypeScript compiling to CommonJS:** use `"module": "node20"` or `"nodenext"` (`node16` fails with TS1479). ESM and bundler setups need no changes, and consumers don't need `experimentalDecorators`.
- **Jest in CommonJS mode:** switch to ESM mode or Vitest, or configure an ESM-to-CommonJS transformer and make sure `transformIgnorePatterns` doesn't exclude the `@peculiar/*` packages, `asn1js` and `tsyringe`.
- **Peer dependencies:** `@peculiar/x509` (`^3.1.0`) is a peer of `-common`, `-marvell` and `-yubico`, and `-marvell` also has `@peculiar/asn1-schema` (`^3.0.0`) and `tsyringe` (`^4.10.0`) as peers. The APIs take and return x509 objects, and Marvell resolves x509's algorithm provider from the tsyringe container that x509 registers into, so an app needs exactly one copy of each. npm 7+ installs peers automatically, and a conflicting version now fails at install (`ERESOLVE`) instead of at runtime. The CLI keeps them as regular dependencies.
- **x509 3 and asn1-schema 3:** certificates and keys from `@peculiar/x509` 2 can't be passed in, so move other libraries that share them to x509 3 at the same time. The Reflect polyfill is still required. If you set `@peculiar/webcrypto` as the crypto provider, use 2.x: next to x509 3, webcrypto 1.x fails ECDSA signing with `Cannot get schema for 'EcDsaSignature' target`.
- **`pvtsutils` and `tslib` are gone;** Marvell uses `@peculiar/utils` 4. `parse()`, `read()` and `verifyEvidence()` now accept a `SharedArrayBuffer` (or a view over one), which 2.x rejected, and invalid UTF-8 in the `OBJ_ATTR_LABEL`/`OBJ_ATTR_ID` text attributes decodes to U+FFFD instead of throwing `URI malformed`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, checks and the release process.

## License

This project is licensed under the [MIT License](LICENSE).
