import {
  AttestationProvider,
  Attestation,
  AttestationVerificationParams,
  AttestationVerificationResult,
} from '@peculiar/attestation-common';
import { MarvellAttestation } from './attestation';
import { MarvellAttestationParser } from './parser';
import { PublicKeyExtractor } from './public_key';
import {
  MarvellAttestationValidator,
  MarvellAttestationValidatorParams,
} from './validator';

export type MarvellAttestationType = Attestation<MarvellAttestation>;
export type MarvellAttestationProviderParams =
  MarvellAttestationValidatorParams;

export class MarvellAttestationProvider implements AttestationProvider {
  format = 'marvell';

  private publicKeyExtractor: PublicKeyExtractor;
  private validator: MarvellAttestationValidator;

  constructor(params: MarvellAttestationProviderParams = {}) {
    this.publicKeyExtractor = new PublicKeyExtractor();
    this.validator = new MarvellAttestationValidator(params);
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

  async verify(
    params: AttestationVerificationParams,
  ): Promise<AttestationVerificationResult> {
    if (params.attestation.format !== this.format) {
      return {
        status: false,
        error: new Error('Invalid attestation format'),
      };
    }

    const { attestation, intermediateCerts } = params;
    const result = await this.validator.validate(
      attestation.metadata,
      intermediateCerts,
    );

    return result;
  }
}
