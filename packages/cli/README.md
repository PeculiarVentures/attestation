<h1 align="center">
  @peculiar/attestation-cli
</h1>

<div align="center">

![NPM License](https://img.shields.io/npm/l/@peculiar/attestation-cli)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/PeculiarVentures/attestation/publish.yml?branch=main&label=publish)
[![npm version](https://img.shields.io/npm/v/@peculiar/attestation-cli.svg)](https://www.npmjs.com/package/@peculiar/attestation-cli)
![Coveralls](https://img.shields.io/coverallsCoverage/github/PeculiarVentures/attestation)
[![npm downloads](https://img.shields.io/npm/dm/@peculiar/attestation-cli.svg)](https://www.npmjs.com/package/@peculiar/attestation-cli)

</div>

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

## Breaking Changes In v3

The `attest` command requires Node.js `^20.19.0 || >=22.12.0` (2.x had no `engines` field) and is now an ES module. Its commands and options are unchanged. See the [full notes](https://github.com/PeculiarVentures/attestation#breaking-changes-in-v3).

- **`marvell verify`** checks the Google Cloud HSM profile and prints separate signature and certificate-trust results. Evidence without the Google owner card and partition certificates now fails (see [Marvell verification](#marvell-verification)).
- **Dependencies:** the CLI uses `@peculiar/x509` 3 and the v3 attestation libraries. Yubico commands still need the native `pkcs11js` module, so don't install with `--ignore-scripts`.

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
format. This command explicitly selects the Google Cloud HSM profile, requiring the
manufacturer card/partition chain, direct Google owner-card and owner-partition
certificates, matching card/partition keys and a valid evidence signature. It uses the
bundled manufacturer and owner trust anchors; the certificate bundle does not replace
or extend that trust configuration. A missing owner component now fails verification.
The generic Marvell profile remains available through the library API.

`marvell info` parses and displays evidence even when its attested public key cannot be
extracted. It reports `Attested public key: unavailable (...)` separately; `info` does
not verify authenticity. `marvell verify` also treats key display as optional, so an
extraction/display error does not change the signature and certificate verification
result or its exit code. A valid evidence signature can therefore be accepted even if
the attested key is symmetric or unsupported for extraction. Invalid signatures and
certificate relationships still fail verification.

Verification prints separate `Signature` and `Certificate trust` states (`PASSED`,
`FAILED` or `NOT EVALUATED`), with a reason for each non-passing check. The final
`Status` and exit code still require both checks to pass for the same signing key.
For example, a valid signature with missing owner certificates reports signature
`PASSED`, certificate trust `FAILED (untrusted-certificates)` and exits with code 1.
A corrupted signature with a complete certificate proof reports signature `FAILED`
and certificate trust `PASSED`; this is also an overall failure.

`marvell key` remains strict: it requires an extractable public key and fails on an
extraction error. No public-key output is written when extraction fails.

## License

This project is licensed under the MIT License.
