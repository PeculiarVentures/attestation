# KMS Attestation Module

[![Coverage Status](https://coveralls.io/repos/github/PeculiarVentures/kms-attestation/badge.svg?branch=main)](https://coveralls.io/github/PeculiarVentures/kms-attestation?branch=main)
[![CI](https://github.com/PeculiarVentures/kms-attestation/actions/workflows/ci.yml/badge.svg)](https://github.com/PeculiarVentures/kms-attestation/actions/workflows/ci.yml)

`@peculiar/kms-attestation` is a library and command-line tool for verifying KMS key attestations and displaying information about attestation certificates. This module provides a comprehensive API for parsing and validating attestation data, as well as a command-line interface (CLI) for performing these tasks.

## Installation

To install the module, use npm:

```bash
npm install @peculiar/kms-attestation
```

## Usage

### Library

The library provides several classes and functions to work with KMS attestation data. Below are some examples of how to use the library.

#### Parsing Attestation Data

To parse attestation data, use the `KmsAttestationParser` class:

```ts
import fs from "node:fs";
import { KmsAttestationParser } from "@peculiar/kms-attestation";

const attestationData = fs.readFileSync("path/to/attestation_data.dat");
const parser = new KmsAttestationParser();
const attestation = parser.parse(attestationData);

console.log(attestation);
```

#### Validating Attestation Data

To validate attestation data, use the `KmsAttestationValidator` class:

```ts
import fs from "node:fs";
import assert from "node:assert";
import { KmsAttestationValidator } from "@peculiar/kms-attestation";

async function main() {
  const attestationData = fs.readFileSync("path/to/attestation_data.dat");
  const certificates = fs.readFileSync(
    "path/to/certificates_chain.crt",
    "utf-8"
  );

  const validator = new KmsAttestationValidator();
  const result = await validator.validate(attestationData, certificates);

  console.log(result);
  assert(result.isValid);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
```

### Command-Line Interface

The module also provides a command-line interface (CLI) for verifying KMS key attestations and displaying information about attestation certificates. For detailed usage instructions, refer to the [CLI Usage Guide](CLI_USAGE.md).

## Additional Resources

For more information on key attestation, you can refer to the following resources:

- [Marvell Software Key Attestation](https://cn.marvell.com/products/security-solutions/nitrox-hs-adapters/software-key-attestation.html)
- [Verifying Attestations (Google Cloud Key Management Service)](https://cloud.google.com/kms/docs/attest-key)

## License

This project is licensed under the MIT License. See the [`LICENSE`](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## Contact

For any questions or issues, please open an issue on GitHub.
