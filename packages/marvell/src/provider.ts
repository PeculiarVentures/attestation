import { type AttestationProvider, type Attestation, type AttestationVerificationParams, type AttestationVerificationResult } from "@peculiar/attestation-common";
import { type MarvellAttestation } from "./attestation";
import { MarvellAttestationParser } from "./parser";
import { PublicKeyExtractor } from "./public_key";
import { MarvellAttestationValidator, type MarvellAttestationValidatorParams } from "./validator";

export type MarvellAttestationType = Attestation<MarvellAttestation>;
export type MarvellAttestationProviderParams = MarvellAttestationValidatorParams;

export class MarvellAttestationProvider implements AttestationProvider {
  format = "marvell";

  private publicKeyExtractor: PublicKeyExtractor;
  private readonly crypto: Crypto;
  private readonly validator: MarvellAttestationValidator;

  constructor(params: MarvellAttestationProviderParams = {}) {
    this.publicKeyExtractor = new PublicKeyExtractor();
    this.crypto = params.crypto ?? crypto;
    this.validator = new MarvellAttestationValidator({
      crypto: this.crypto,
      trustedCerts: params.trustedCerts === undefined ? undefined : [...params.trustedCerts],
    });
  }

  async read(data: BufferSource): Promise<MarvellAttestationType> {
    const parser = new MarvellAttestationParser();
    const attest = parser.parse(data);
    const publicKey = this.publicKeyExtractor.extractPublicKey(attest);

    return {
      format: this.format,
      publicKey,
      metadata: attest,
    };
  }

  async verify(params: AttestationVerificationParams): Promise<AttestationVerificationResult> {
    if (params.attestation.format !== this.format) {
      return {
        status: false,
        error: new Error("Invalid attestation format"),
      };
    }

    try {
      const { attestation, intermediateCerts, trustedCerts } = params;
      // An explicit trust set replaces defaults for this call without changing shared provider state.
      const validator = trustedCerts === undefined ? this.validator : new MarvellAttestationValidator({ crypto: this.crypto, trustedCerts: [...trustedCerts] });
      return await validator.validate(attestation.metadata as MarvellAttestation, intermediateCerts);
    } catch (error) {
      // Invalid per-call trust configuration follows the verification-result contract too.
      return { status: false, error: error instanceof Error ? error : new Error(String(error)) };
    }
  }
}
