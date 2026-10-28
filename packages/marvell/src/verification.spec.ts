import { beforeAll, describe, expect, expectTypeOf, it, vi } from "vitest";
import { gunzipSync } from "node:zlib";
import * as x509 from "@peculiar/x509";
import { Crypto as PeculiarCrypto } from "@peculiar/webcrypto";
import type { AttestationProvider, AttestationVerificationResult } from "@peculiar/attestation-common";
import { MarvellAttestationProvider, type GoogleCloudHsmTrust, type MarvellAttestation, type MarvellAttestationVerificationResult, type MarvellEvidenceVerificationParams } from "./index";
import { base64CompressedData } from "../test/fixtures";

type Profile = "generic" | "google-cloud-hsm";
const profiles: Profile[] = ["generic", "google-cloud-hsm"];
let trust: GoogleCloudHsmTrust;
let certs: x509.X509Certificate[];
let wrongProof: x509.X509Certificate[];
let ecProof: x509.X509Certificate[];
let untrustedSigner: x509.X509Certificate;
let evidence: Uint8Array<ArrayBuffer>;
let wrongModulus: string;

async function issue(subject: string, keys: CryptoKeyPair, issuer: string, signingKeys: CryptoKeyPair): Promise<x509.X509Certificate> {
  return x509.X509CertificateGenerator.create(
    {
      subject: `CN=${subject}`,
      issuer: `CN=${issuer}`,
      publicKey: keys.publicKey,
      signingKey: signingKeys.privateKey,
      signingAlgorithm: { name: signingKeys.privateKey.algorithm.name, hash: "SHA-256" },
      notBefore: new Date("2024-01-01"),
      notAfter: new Date("2099-01-01"),
    },
    crypto,
  );
}

function roots(profile: Profile): NonNullable<MarvellEvidenceVerificationParams["trustedCerts"]> {
  return profile === "generic" ? [trust.manufacturerRoot, trust.ownerRoot] : trust;
}

function provider(profile: Profile, customCrypto?: Crypto): MarvellAttestationProvider {
  return profile === "generic"
    ? new MarvellAttestationProvider({ trustedCerts: [trust.manufacturerRoot, trust.ownerRoot], crypto: customCrypto })
    : new MarvellAttestationProvider({ profile, trustedCerts: trust, crypto: customCrypto });
}

function failure(result: MarvellAttestationVerificationResult): Extract<MarvellAttestationVerificationResult, { status: false }> {
  expect(result.status).toBe(false);
  if (result.status) throw new Error("Expected failure");
  expect(result.signer).toBeUndefined();
  expect(result.chain).toBeUndefined();
  return result;
}

function corrupted(): Uint8Array<ArrayBuffer> {
  const bytes = evidence.slice();
  bytes[bytes.length - 1] ^= 1;
  return bytes;
}

beforeAll(async () => {
  const [manufacturer, owner, card, ecPartition] = await Promise.all(Array.from({ length: 4 }, () => crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])));
  const [partition, wrongPartition] = await Promise.all(
    Array.from({ length: 2 }, () =>
      crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]),
    ),
  );
  trust = { manufacturerRoot: await issue("Manufacturer", manufacturer, "Manufacturer", manufacturer), ownerRoot: await issue("Owner", owner, "Owner", owner) };
  const manufacturerCard = await issue("Card", card, "Manufacturer", manufacturer);
  const ownerCard = await issue("Card", card, "Owner", owner);
  certs = [manufacturerCard, await issue("Partition", partition, "Card", card), ownerCard, await issue("Partition", partition, "Owner", owner)];
  wrongProof = [manufacturerCard, await issue("Other partition", wrongPartition, "Card", card), ownerCard, await issue("Other partition", wrongPartition, "Owner", owner)];
  ecProof = [manufacturerCard, await issue("EC partition", ecPartition, "Card", card), ownerCard, await issue("EC partition", ecPartition, "Owner", owner)];
  untrustedSigner = await issue("Untrusted partition", partition, "Unrelated authority", card);
  wrongModulus = (await crypto.subtle.exportKey("jwk", wrongPartition.publicKey)).n!;
  evidence = Uint8Array.from(gunzipSync(Buffer.from(base64CompressedData, "base64")));
  const signature = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, partition.privateKey, evidence.subarray(0, -256));
  evidence.set(new Uint8Array(signature), evidence.length - 256);
});

it("returns a covariant Marvell result without changing common provider types", async () => {
  expectTypeOf<MarvellAttestationVerificationResult>().toExtend<AttestationVerificationResult>();
  expectTypeOf<MarvellAttestationProvider>().toExtend<AttestationProvider>();
  expectTypeOf<ReturnType<MarvellAttestationProvider["verify"]>>().toEqualTypeOf<Promise<MarvellAttestationVerificationResult>>();
  expectTypeOf<ReturnType<MarvellAttestationProvider["verifyEvidence"]>>().toEqualTypeOf<Promise<MarvellAttestationVerificationResult>>();
  expectTypeOf<ReturnType<AttestationProvider["verify"]>>().toEqualTypeOf<Promise<AttestationVerificationResult>>();
  const instance = provider("generic");
  const shared: AttestationProvider = instance;
  const attestation = await shared.read(evidence);
  expect((await shared.verify({ attestation, intermediateCerts: certs })).status).toBe(true);
  const rich = await instance.verify({ attestation, intermediateCerts: certs });
  if (rich.status) {
    expectTypeOf(rich.signature.status).toEqualTypeOf<"passed">();
    expectTypeOf(rich.trust.status).toEqualTypeOf<"passed">();
  }
});

describe.each(profiles)("Explicit verification checks (%s)", (profile) => {
  it("passes only when the signature and policy pass for the same key", async () => {
    const result = await provider(profile).verifyEvidence({ evidence, intermediateCerts: certs });
    expect(result).toMatchObject({ status: true, signature: { status: "passed" }, trust: { status: "passed" } });
    expect(result.signer?.equal(certs[1])).toBe(true);
  });

  it("reports a conclusive signature mismatch with a trusted certificate proof", async () => {
    const result = failure(await provider(profile).verifyEvidence({ evidence: corrupted(), intermediateCerts: certs }));
    expect(result.signature).toMatchObject({ status: "failed", reason: "invalid-signature" });
    expect(result.trust.status).toBe("passed");
    expect(result.candidate?.certificates).toHaveLength(2);
    expect(result.candidate?.chain?.[0].equal(trust.manufacturerRoot)).toBe(true);
  });

  it("reports a valid signature independently of missing trust paths", async () => {
    const result = failure(await provider(profile).verifyEvidence({ evidence, intermediateCerts: [untrustedSigner] }));
    expect(result.signature.status).toBe("passed");
    expect(result.trust).toMatchObject({ status: "failed", reason: "untrusted-certificates" });
    expect(result.candidate?.certificates).toEqual([untrustedSigner]);
    expect(result.candidate?.chain).toBeUndefined();
  });

  it("never borrows trust from a different key with an invalid signature", async () => {
    const results = await Promise.all(
      [[untrustedSigner, ...wrongProof], [...wrongProof].reverse().concat(untrustedSigner)].map((pool) => provider(profile).verifyEvidence({ evidence, intermediateCerts: pool })),
    );
    for (const item of results) {
      const result = failure(item);
      expect(result.signature.status).toBe("passed");
      expect(result.trust).toMatchObject({ status: "failed", reason: "untrusted-certificates" });
      expect(result.candidate?.certificates).toEqual([untrustedSigner]);
    }
  });

  it("reports both conclusive failures when the sole key mismatches and has no trusted proof", async () => {
    const result = failure(await provider(profile).verifyEvidence({ evidence: corrupted(), intermediateCerts: [untrustedSigner] }));
    expect(result.signature).toMatchObject({ status: "failed", reason: "invalid-signature" });
    expect(result.trust).toMatchObject({ status: "failed", reason: "untrusted-certificates" });
  });

  it.each(["empty", "anchors only"])("does not label an %s signer pool as a bad signature", async (kind) => {
    const pool = kind === "empty" ? [] : [trust.manufacturerRoot, trust.ownerRoot];
    const result = failure(await provider(profile).verifyEvidence({ evidence, intermediateCerts: pool }));
    expect(result.signature).toMatchObject({ status: "not-evaluated", reason: "missing-signer" });
    expect(result.trust).toMatchObject({ status: "not-evaluated", reason: "missing-signer" });
    expect(result.candidate).toBeUndefined();
  });

  it("distinguishes unsupported evidence-signing keys from invalid signatures", async () => {
    const result = failure(await provider(profile).verifyEvidence({ evidence, intermediateCerts: ecProof }));
    expect(result.signature).toMatchObject({ status: "not-evaluated", reason: "unsupported-algorithm" });
    expect(result.trust.status).toBe("passed");
  });

  it("does not invent a signer identity from multiple conclusive mismatches", async () => {
    const result = failure(await provider(profile).verifyEvidence({ evidence: corrupted(), intermediateCerts: [...certs, ...wrongProof] }));
    expect(result.signature).toMatchObject({ status: "failed", reason: "invalid-signature" });
    expect(result.trust.status).toBe("passed");
    expect(result.candidate).toBeUndefined();
  });

  it("does not make same-key and DER duplicate certificates ambiguous", async () => {
    const duplicate = new x509.X509Certificate(certs[1].rawData);
    const result = failure(await provider(profile).verifyEvidence({ evidence: corrupted(), intermediateCerts: [...certs, duplicate, certs[3]] }));
    expect(result.signature.status).toBe("failed");
    expect(result.trust.status).toBe("passed");
    expect(result.candidate?.certificates).toHaveLength(2);
  });

  it.each(["raw", "parsed"])("classifies malformed %s evidence without a signature mismatch", async (kind) => {
    const input = kind === "raw" ? new Uint8Array(0) : ({ signedData: "not bytes", signature: new Uint8Array(256) } as unknown as MarvellAttestation);
    const result = failure(await provider(profile).verifyEvidence({ evidence: input, intermediateCerts: certs }));
    expect(result.signature).toMatchObject({ status: "not-evaluated", reason: "malformed-evidence" });
    expect(result.trust).toMatchObject({ status: "not-evaluated", reason: "malformed-evidence" });
  });

  it("classifies invalid per-call trust before evaluating cryptography", async () => {
    const result = failure(await provider(profile).verifyEvidence({ evidence, intermediateCerts: certs, trustedCerts: [] }));
    expect(result.signature).toMatchObject({ status: "not-evaluated", reason: "invalid-trust-configuration" });
    expect(result.trust).toMatchObject({ status: "not-evaluated", reason: "invalid-trust-configuration" });
  });

  it("retains explicit format rejection before trust overrides", async () => {
    const instance = provider(profile);
    const attestation = { ...(await instance.read(evidence)), format: "piv" };
    const result = failure(await instance.verify({ attestation, intermediateCerts: certs, trustedCerts: [] }));
    expect(result.signature).toMatchObject({ status: "not-evaluated", reason: "invalid-format" });
    expect(result.trust).toMatchObject({ status: "not-evaluated", reason: "invalid-format" });
  });

  it("treats mismatch plus an uncheckable plausible RSA key as ambiguous, regardless of order", async () => {
    const custom = new PeculiarCrypto() as unknown as Crypto;
    const original = custom.subtle.verify.bind(custom.subtle);
    vi.spyOn(custom.subtle, "verify").mockImplementation(async (algorithm, key, signature, data) => {
      if (key.algorithm.name === "RSASSA-PKCS1-v1_5" && (await custom.subtle.exportKey("jwk", key)).n === wrongModulus) throw new Error("RSA provider failed");
      return original(algorithm, key, signature, data);
    });
    const instance = provider(profile, custom);
    const pool = [...certs, ...wrongProof];
    const results = await Promise.all([pool, [...pool].reverse()].map((intermediateCerts) => instance.verifyEvidence({ evidence: corrupted(), intermediateCerts })));
    for (const item of results) {
      const result = failure(item);
      expect(result.signature).toMatchObject({ status: "not-evaluated", reason: "ambiguous-signer" });
      expect(result.trust.status).toBe("passed");
      expect(result.candidate).toBeUndefined();
    }
  });

  it("reports unavailable RSA support without claiming a mismatch", async () => {
    const custom = new PeculiarCrypto() as unknown as Crypto;
    const original = custom.subtle.verify.bind(custom.subtle);
    vi.spyOn(custom.subtle, "verify").mockImplementation(async (algorithm, key, signature, data) => {
      if (key.algorithm.name === "RSASSA-PKCS1-v1_5") throw new DOMException("RSA not available", "NotSupportedError");
      return original(algorithm, key, signature, data);
    });
    const result = failure(await provider(profile, custom).verifyEvidence({ evidence, intermediateCerts: certs }));
    expect(result.signature).toMatchObject({ status: "not-evaluated", reason: "unsupported-algorithm" });
    expect(result.trust.status).toBe("passed");
  });

  it("keeps a valid signature when certificate verification throws", async () => {
    const custom = new PeculiarCrypto() as unknown as Crypto;
    const original = custom.subtle.verify.bind(custom.subtle);
    vi.spyOn(custom.subtle, "verify").mockImplementation(async (algorithm, key, signature, data) => {
      if (key.algorithm.name === "ECDSA") throw new Error("Certificate crypto unavailable");
      return original(algorithm, key, signature, data);
    });
    const result = failure(await provider(profile, custom).verifyEvidence({ evidence, intermediateCerts: certs }));
    expect(result.signature.status).toBe("passed");
    expect(result.trust).toMatchObject({ status: "not-evaluated", reason: "verification-error" });
    if (profile === "generic" && result.trust.status !== "passed") expect(result.trust.error).toBeInstanceOf(x509.X509ChainBuildError);
  });

  it("classifies certificate-pool limits as not evaluated", async () => {
    const result = failure(await provider(profile).verifyEvidence({ evidence, intermediateCerts: Array(65).fill(certs[1]) }));
    expect(result.signature).toMatchObject({ status: "not-evaluated", reason: "resource-limit" });
    expect(result.trust).toMatchObject({ status: "not-evaluated", reason: "resource-limit" });
  });

  it("retains per-call trust replacement without altering subsequent result states", async () => {
    const instance = new MarvellAttestationProvider({ profile });
    const results = await Promise.all([instance.verifyEvidence({ evidence, intermediateCerts: certs, trustedCerts: roots(profile) }), instance.verifyEvidence({ evidence, intermediateCerts: certs })]);
    expect(results[0]).toMatchObject({ status: true, signature: { status: "passed" }, trust: { status: "passed" } });
    expect(results[1]).toMatchObject({ status: false, signature: { status: "passed" }, trust: { status: "failed" } });
  });
});

it.each([0, 1, 2, 3])("verifies the signature with Google role %i missing", async (missing) => {
  const result = failure(await provider("google-cloud-hsm").verifyEvidence({ evidence, intermediateCerts: certs.filter((_, i) => i !== missing) }));
  expect(result.signature.status).toBe("passed");
  expect(result.trust).toMatchObject({ status: "failed", reason: "untrusted-certificates" });
});

it("omits candidate identity when another policy search is incomplete despite conclusive mismatches", async () => {
  const build = x509.X509ChainBuilder.prototype.buildToAnchor;
  const limited = vi.spyOn(x509.X509ChainBuilder.prototype, "buildToAnchor").mockImplementation(async function (this: x509.X509ChainBuilder, cert, params, customCrypto) {
    if (cert.publicKey.equal(wrongProof[1].publicKey)) throw new x509.X509ChainBuildError({ code: "LIMIT_EXCEEDED", limit: "maxDepth" });
    return build.call(this, cert, params, customCrypto);
  });
  try {
    const result = failure(await provider("generic").verifyEvidence({ evidence: corrupted(), intermediateCerts: [...certs, ...wrongProof] }));
    expect(result.signature).toMatchObject({ status: "failed", reason: "invalid-signature" });
    expect(result.trust.status).toBe("passed");
    expect(result.candidate).toBeUndefined();
  } finally {
    limited.mockRestore();
  }
});
