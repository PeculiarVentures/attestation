# Attestation

[![Coverage Status](https://coveralls.io/repos/github/PeculiarVentures/attestation/badge.svg?branch=ci-fix-auth)](https://coveralls.io/github/PeculiarVentures/attestation?branch=ci-fix-auth)

This repository contains a collection of libraries and tools for verifying HSM attestation files from various HSMs, including support for certificate chain validation and attestation data extraction.

## Packages

### @peculiar/attestation-common

A common module providing tools and interfaces for verifying HSM attestation files from various HSMs, including support for certificate chain validation and attestation data extraction.

[Read more](packages/common/README.md)

### @peculiar/attestation-marvell

A library providing tools to verify HSM attestation files from various HSMs that support Marvell attestation, including support for certificate chain validation and attestation data extraction.

[Read more](packages/marvell/README.md)

### @peculiar/attestation-yubico

A library providing tools to verify PIV attestation files from Yubico, including support for certificate chain validation and attestation data extraction.

[Read more](packages/yubico/README.md)

### @peculiar/attestation-cli

This utility is designed for verifying attestation data in various formats. It supports multiple attestation providers and offers a range of commands to interact with attestation files and certificates.

[Read more](packages/cli/README.md)

## Development

Install dependencies with `npm ci`. Run `npm run lint` to check code with Oxlint, `npm run format` to apply Oxfmt formatting, and `npm run format:check` to verify formatting without changing files. Use `npm test` and `npm run build` to validate changes.

## License

This project is licensed under the MIT License.

## Module compatibility

The packages ship as ES modules and support Node.js ^20.19.0 or >=22.12.0. CommonJS consumers can use `require()` on these versions. The package entry points are defined by `exports`; importing internal build paths is unsupported. TypeScript CommonJS consumers should use `module: node20` or `nodenext` with compatible TypeScript.
