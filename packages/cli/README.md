# Attestation Utility

This utility is designed for verifying attestation data in various formats. It supports multiple attestation providers and offers a range of commands to interact with attestation files and certificates.

## Common Purposes

- **Verify Attestation Data**: Ensure the integrity and authenticity of attestation data using trusted certificates.
- **Detail Attestation Information**: Extract and display detailed information from attestation files.
- **Export Public Keys**: Extract public keys from attestation files and optionally compare them with source keys or save them to a file.
- **Certificate Management**: Detail and manage certificates used in the attestation process.

## Installation

To install the utility, use npm:

```sh
npm install @peculiar/attestation-cli
```

## Usage

To get started, you can use the `--help` flag to see the available commands and options:

```sh
attest --help
```

For detailed information on a specific command, use the `--help` flag with the command:

```sh
attest <command> --help
```

## Marvell verification

```sh
attest marvell verify evidence.bin --cert certificates.pem
```

`--cert` supplies the untrusted signing and intermediate certificate bundle in PEM
format. Verification uses the bundled manufacturer and owner trust anchors; the
certificate bundle does not replace or extend that trust configuration.

## License

This project is licensed under the MIT License.
