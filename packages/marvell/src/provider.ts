import { type AttestationProvider, type Attestation, type AttestationVerificationParams, type AttestationVerificationResult } from "@peculiar/attestation-common";
import { type PublicKey, type X509Certificate } from "@peculiar/x509";
import { BufferSourceConverter } from "pvtsutils";
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

/** Verification does not require extraction or interpretation of the attested public key. */
export type MarvellEvidenceVerificationParams = Omit<MarvellAttestationVerificationParams, "attestation"> & {
  evidence: MarvellAttestation | BufferSource;
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

  /** Parses evidence without extracting its attested key or establishing trust. Parsing errors throw. */
  parse(data: BufferSource): MarvellAttestation {
    return new MarvellAttestationParser().parse(data);
  }

  /** Extracts the attested public key; extraction errors are independent of evidence verification. */
  extractPublicKey(evidence: MarvellAttestation): PublicKey {
    return this.publicKeyExtractor.extractPublicKey(evidence);
  }

  /** Retains the shared read() contract: parsing and key extraction must both succeed. */
  async read(data: BufferSource): Promise<MarvellAttestationType> {
    const evidence = this.parse(data);
    return {
      format: this.format,
      publicKey: this.extractPublicKey(evidence),
      metadata: evidence,
    };
  }

  async verify(params: MarvellAttestationVerificationParams): Promise<AttestationVerificationResult> {
    if (params.attestation.format !== this.format) {
      return {
        status: false,
        error: new Error("Invalid attestation format"),
      };
    }

    return this.verifyEvidence({
      evidence: params.attestation.metadata as MarvellAttestation,
      intermediateCerts: params.intermediateCerts,
      trustedCerts: params.trustedCerts,
    });
  }

  /** Verifies evidence signatures and the configured certificate policy without extracting the attested key. */
  async verifyEvidence(params: MarvellEvidenceVerificationParams): Promise<AttestationVerificationResult> {
    try {
      const { evidence, intermediateCerts, trustedCerts } = params;
      // An explicit trust set replaces defaults for this call without changing shared provider state.
      const validator = trustedCerts === undefined ? this.validator : this.createValidator(trustedCerts);
      const parsed = BufferSourceConverter.isBufferSource(evidence) ? this.parse(evidence as BufferSource) : (evidence as MarvellAttestation);
      return await validator.validate(parsed, intermediateCerts);
    } catch (error) {
      // Parsing and invalid per-call trust configuration follow the verification-result contract too.
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
