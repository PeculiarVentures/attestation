# CLI Usage Guide

`@peculiar/kms-attestation` provides a command-line interface (CLI) for verifying KMS key attestations and displaying information about attestation certificates.

## Installation

To use the CLI, make sure you have installed `@peculiar/kms-attestation` globally or locally in your project.

```bash
npm install @peculiar/kms-attestation
```

## Commands

### General Usage

```bash
kms-attestation -h
```

```
Usage: kms-attestation [options] [command]

Utility for verifying KMS key attestation

Options:
  -V, --version            output the version number
  -h, --help               display help for command

Commands:
  verify [options] <file>  Verify the key attestation
  show-cert <file>         Display information about the attestation certificates
  show-info <file>         Display information about the key attestation
  help [command]           display help for command
```

### Verify

Verify the key attestation.

```bash
kms-attestation verify [options] <file>
```

**Arguments:**

- `file` - The file containing the key attestation.

**Options:**

- `-c, --certs <file>` - The file containing the attestation certificates.
- `-m, --mfr [file]` - The file containing the manufacturer root certificate.
- `-o, --owner [file]` - The file containing the owner root certificate.
- `--info` - Output information about the attestation.
- `-h, --help` - Display help for command.

**Example:**

```bash
kms-attestation verify -c data/certificates_chain.crt -m data/mfr_root.crt -o data/owner_root.crt data/attestation_data.dat
```

**Output:**

```
Attestation: PASSED
```

### Show Certificate

Display information about the attestation certificates.

```bash
kms-attestation show-cert [options] <file>
```

**Arguments:**

- `file` - The file containing the attestation certificates.

**Options:**

- `-h, --help` - Display help for command.

**Example:**

```bash
kms-attestation show-cert data/certificates_chain.crt
```

**Output:**

```
Certificate:
  Data:
    Version: v3 (2)
    Serial Number:
      01
    Signature Algorithm: sha256WithRSAEncryption
    Issuer: C=US+ST=CA+O=Cavium+OU=N3FIPS+L=SanJose, CN=HSM:5.3G1953-ICM001225\, for FIPS mode
    Validity:
      Not Before: Mon, 15 Apr 2024 18:19:15 GMT
      Not After: Thu, 13 Apr 2034 18:19:15 GMT
    Subject: C=US+ST=CA+O=Cavium+OU=N3FIPS+L=SanJose, CN=HSM:5.3G1953-ICM001225:PARTN:1\, for FIPS mode
    Subject Public Key Info:
      Algorithm: rsaEncryption
      Raw Data:
        30 82 01 0a 02 82 01 01  00 f5 3d 27 48 12 e8 f2
        48 49 8a a0 b1 d3 f3 9c  3b df 14 7d 1c e9 f8 05
        ...
```

### Show Information

Display information about the key attestation.

```bash
kms-attestation show-info [options] <file>
```

**Arguments:**

- `file` - The file containing the key attestation.

**Options:**

- `-h, --help` - Display help for command.

**Example:**

```bash
kms-attestation show-info data/attestation_data.dat
```

**Output:**

```
Key Attestation:
  Compressed: true
  Response Header:
    Code: 0
    Flags: KEY_GEN_FLAG_GET_ATTR | KEY_GEN_FLAG_GET_ATTEST
    Buffer Size: 1824 bytes
    Total Size: 2112 bytes
  Key Attestation Data:
    Version: v1
    Flags: KEY_GEN_FLAG_GET_ATTR | KEY_GEN_FLAG_GET_ATTEST
    First Key:
      Handle: 0x000007e6
      Object Size: 896 bytes
      Attribute Count: 35
      Attributes:
        OBJ_ATTR_CLASS: CKO_PUBLIC_KEY
        OBJ_ATTR_TOKEN: true
        OBJ_ATTR_PRIVATE: true
        OBJ_ATTR_LABEL: app_key
        OBJ_ATTR_TRUSTED: false
        OBJ_ATTR_KEY_TYPE: CKK_EC
        OBJ_ATTR_ID: d06cc801f7dffdbdd7a9240bdc0ae1ad124862980ca732ce5446f1cd0b7dd7aab3e31db29582a0bb84cb1d78d17b66cc6be625ae3e74d3969f1d3e087387c7b
        OBJ_ATTR_SENSITIVE: false
        OBJ_ATTR_ENCRYPT: true
        OBJ_ATTR_DECRYPT: false
        OBJ_ATTR_WRAP: true
        OBJ_ATTR_UNWRAP: false
        OBJ_ATTR_SIGN: false
        OBJ_ATTR_VERIFY: true
        OBJ_ATTR_DERIVE: false
        OBJ_ATTR_MODULUS: 0448325169a37687389bf6de2febaf15985d0352708bbe022b2b9c4c6efb78dc7fd54e0d20a3aa6e06ee53b1052f611a0d42b61081498db789c09756b8010ada70
        OBJ_ATTR_MODULUS_BITS: 415
        OBJ_ATTR_VALUE_LEN: 65
        OBJ_ATTR_EXTRACTABLE: true
        OBJ_ATTR_LOCAL: true
        OBJ_ATTR_NEVER_EXTRACTABLE: false
        OBJ_ATTR_ALWAYS_SENSITIVE: false
        OBJ_ATTR_KCV: 81b1a7
        OBJ_ATTR_WRAP_WITH_TRUSTED: false
        OBJ_EXT_ATTR1: 0000000000000002
        OBJ_ATTR_EKCV: 4075a3e5a13e33095430962abcbacbef32d7737234868785d2420893293fc86a
        OBJ_ATTR_SPLITTABLE: false
        OBJ_ATTR_IS_SPLIT: false
        OBJ_ATTR_ENCRYPT_KEY_MECHANISMS: 00000000000000000000000000000000000000000000000000000000000000ff
        OBJ_ATTR_DECRYPT_KEY_MECHANISMS: 00000000000000000000000000000000000000000000000000000000000000ff
        OBJ_ATTR_SIGN_KEY_MECHANISMS: 00000000000000000000000000000000000000000000000000000000000000ff
        OBJ_ATTR_VERIFY_KEY_MECHANISMS: 00000000000000000000000000000000000000000000000000000000000000ff
        OBJ_ATTR_WRAP_KEY_MECHANISMS: 00000000000000000000000000000000000000000000000000000000000000ff
        OBJ_ATTR_UNWAP_KEY_MECHANISMS: 00000000000000000000000000000000000000000000000000000000000000ff
        OBJ_ATTR_DERIVE_KEY_MECHANISMS: 00000000000000000000000000000000000000000000000000000000000000ff
```

## Summary

This guide provides an overview of the commands available in the `@peculiar/kms-attestation` CLI. Use the `--help` option with any command to get more details about its usage and options. If you encounter any issues or need further assistance, please refer to the project's documentation or reach out to the support team.
