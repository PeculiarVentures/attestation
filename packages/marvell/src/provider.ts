import { type AttestationProvider, type Attestation, type AttestationVerificationParams, type AttestationVerificationResult } from "@peculiar/attestation-common";
import { type X509Certificate } from "@peculiar/x509";
import { GoogleCloudHsmAttestationValidator, type GoogleCloudHsmTrust } from "./google_cloud_hsm";
import { type MarvellAttestation } from "./attestation";
import { MarvellAttestationParser } from "./parser";
import { PublicKeyExtractor } from "./public_key";
import { MarvellAttestationValidator, type MarvellAttestationValidatorParams } from "./validator";

export type MarvellAttestationType = Attestation<MarvellAttestation>;
export type { GoogleCloudHsmTrust } from "./google_cloud_hsm";

export type MarvellAttestationProviderParams = (MarvellAttestationValidatorParams & { profile?: "generic" }) | { profile: "google-cloud-hsm"; crypto?: Crypto; trustedCerts?: GoogleCloudHsmTrust };

export type MarvellAttestationVerificationParams = Omit<AttestationVerificationParams, "trustedCerts"> & {
  trustedCerts?: X509Certificate[] | GoogleCloudHsmTrust;
};

export class MarvellAttestationProvider implements AttestationProvider {
  format = "marvell";

  private publicKeyExtractor: PublicKeyExtractor;
  private readonly crypto: Crypto;
  private readonly validator: MarvellAttestationValidator | GoogleCloudHsmAttestationValidator;
  private readonly profile: "generic" | "google-cloud-hsm";

  constructor(params: MarvellAttestationProviderParams = {}) {
    this.publicKeyExtractor = new PublicKeyExtractor();
    this.crypto = params.crypto ?? crypto;
    const profile = params.profile === undefined ? "generic" : params.profile;
    if (profile !== "generic" && profile !== "google-cloud-hsm") throw new TypeError("Unsupported Marvell validation profile.");
    this.profile = profile;
    this.validator = this.createValidator(params.trustedCerts);
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

  async verify(params: MarvellAttestationVerificationParams): Promise<AttestationVerificationResult> {
    if (params.attestation.format !== this.format) {
      return {
        status: false,
        error: new Error("Invalid attestation format"),
      };
    }

    try {
      const { attestation, intermediateCerts, trustedCerts } = params;
      // An explicit trust set replaces defaults for this call without changing shared provider state.
      const validator = trustedCerts === undefined ? this.validator : this.createValidator(trustedCerts);
      return await validator.validate(attestation.metadata as MarvellAttestation, intermediateCerts);
    } catch (error) {
      // Invalid per-call trust configuration follows the verification-result contract too.
      return { status: false, error: error instanceof Error ? error : new Error(String(error)) };
    }
  }

  private createValidator(trustedCerts: MarvellAttestationVerificationParams["trustedCerts"]): MarvellAttestationValidator | GoogleCloudHsmAttestationValidator {
    if (this.profile === "google-cloud-hsm") {
      if (Array.isArray(trustedCerts)) throw new TypeError("Google Cloud HSM trustedCerts must name manufacturerRoot and ownerRoot.");
      return new GoogleCloudHsmAttestationValidator({ crypto: this.crypto, trustedCerts });
    }
    if (trustedCerts !== undefined && !Array.isArray(trustedCerts)) throw new TypeError("Generic Marvell trustedCerts must be a certificate array.");
    return new MarvellAttestationValidator({ crypto: this.crypto, trustedCerts: trustedCerts === undefined ? undefined : [...trustedCerts] });
  }
}
