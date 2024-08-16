# Attestation

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

## License

This project is licensed under the MIT License.
