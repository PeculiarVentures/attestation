import { beforeAll, describe, expect, expectTypeOf, it, vi } from "vitest";
import { gunzipSync } from "node:zlib";
import * as x509 from "@peculiar/x509";
import { AsnConvert } from "@peculiar/asn1-schema";
import { AlgorithmIdentifier, Certificate } from "@peculiar/asn1-x509";
import { Crypto as PeculiarCrypto } from "@peculiar/webcrypto";
import type { AttestationProvider, AttestationVerificationResult } from "@peculiar/attestation-common";
import { MarvellAttestationProvider, type GoogleCloudHsmTrust, type MarvellAttestationProviderParams } from "./provider";
import { MANUFACTURER_ROOT_CERT, OWNER_ROOT_CERT } from "./certs";
import { base64CompressedData, certChain } from "../test/fixtures";

const bundledTrust = { manufacturerRoot: MANUFACTURER_ROOT_CERT, ownerRoot: OWNER_ROOT_CERT };
const realEvidence = Buffer.from(base64CompressedData, "base64");
const realCertificates = x509.PemConverter.decode(certChain).map((cert) => new x509.X509Certificate(cert));
const roles = ["manufacturer-card", "manufacturer-partition", "owner-card", "owner-partition"];
let manufacturer: CryptoKeyPair;
let owner: CryptoKeyPair;
let card: CryptoKeyPair;
let partition: CryptoKeyPair;
let other: CryptoKeyPair;
let trust: GoogleCloudHsmTrust;
let certificates: x509.X509Certificate[];
let evidence: Uint8Array<ArrayBuffer>;
let serial = 0;

async function issue(subject: string, keys: CryptoKeyPair, issuer: string, signingKeys: CryptoKeyPair, extensions: x509.Extension[] = []): Promise<x509.X509Certificate> {
  return x509.X509CertificateGenerator.create(
    {
      serialNumber: (++serial).toString(16).padStart(4, "0"),
      subject: `CN=${subject}`,
      issuer: `CN=${issuer}`,
      publicKey: keys.publicKey,
      signingKey: signingKeys.privateKey,
      signingAlgorithm: { name: signingKeys.privateKey.algorithm.name, hash: "SHA-256" },
      notBefore: new Date("2024-01-01T00:00:00Z"),
      notAfter: new Date("2099-01-01T00:00:00Z"),
      extensions,
    },
    crypto,
  );
}

async function signedEvidence(keys: CryptoKeyPair): Promise<Uint8Array<ArrayBuffer>> {
  const bytes = new Uint8Array(gunzipSync(realEvidence));
  const signature = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, keys.privateKey, bytes.subarray(0, -256));
  bytes.set(new Uint8Array(signature), bytes.length - 256);
  return bytes;
}

async function verify(certs: x509.X509Certificate[], bytes: Uint8Array = evidence, roots: GoogleCloudHsmTrust = trust): Promise<AttestationVerificationResult> {
  const provider = new MarvellAttestationProvider({ profile: "google-cloud-hsm", trustedCerts: roots });
  return provider.verify({ attestation: await provider.read(bytes as BufferSource), intermediateCerts: certs });
}

function ids(certs: x509.X509Certificate[]): string[] {
  return certs.map((cert) => cert.toString("hex"));
}

function corrupt(cert: x509.X509Certificate): x509.X509Certificate {
  const bytes = new Uint8Array(cert.rawData.slice(0));
  bytes[bytes.length - 1] ^= 1;
  return new x509.X509Certificate(bytes);
}

function permutations<T>(items: T[]): T[][] {
  if (!items.length) return [[]];
  return items.flatMap((item, i) => permutations([...items.slice(0, i), ...items.slice(i + 1)]).map((rest) => [item].concat(rest)));
}

beforeAll(async () => {
  [manufacturer, owner, other] = await Promise.all(Array.from({ length: 3 }, () => crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])));
  [card, partition] = await Promise.all(
    Array.from({ length: 2 }, () =>
      crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]),
    ),
  );
  trust = { manufacturerRoot: await issue("Manufacturer", manufacturer, "Manufacturer", manufacturer), ownerRoot: await issue("Owner", owner, "Owner", owner) };
  certificates = [
    await issue("Card", card, "Manufacturer", manufacturer),
    await issue("Partition", partition, "Card", card),
    await issue("Card", card, "Owner", owner),
    await issue("Partition", partition, "Owner", owner),
  ];
  evidence = await signedEvidence(partition);
});

describe("Google Cloud HSM certificate relationships", () => {
  it("accepts the real Google bundle with bundled role-bound anchors", async () => {
    const provider: AttestationProvider = new MarvellAttestationProvider({ profile: "google-cloud-hsm" });
    expectTypeOf<MarvellAttestationProvider>().toExtend<AttestationProvider>();
    const result = await provider.verify({ attestation: await provider.read(realEvidence), intermediateCerts: realCertificates });
    expect(result.status).toBe(true);
    expect(ids(result.chain!)).toEqual(ids([MANUFACTURER_ROOT_CERT, realCertificates[1], realCertificates[0]]));
    expect(result.signer?.equal(realCertificates[0])).toBe(true);
  });

  it.each(roles)("rejects the real bundle without %s", async (role) => {
    const indices = [1, 0, 3, 2];
    const missing = indices[roles.indexOf(role)];
    expect(
      (
        await verify(
          realCertificates.filter((_, i) => i !== missing),
          realEvidence,
          bundledTrust,
        )
      ).status,
    ).toBe(false);
  });

  it.each(roles)("rejects a damaged %s signature", async (role) => {
    const pool = [...certificates];
    const index = roles.indexOf(role);
    pool[index] = corrupt(pool[index]);
    expect((await verify(pool)).status).toBe(false);
  });

  it("requires direct owner-partition certification even when an indirect generic path exists", async () => {
    const pool = realCertificates.filter((_, i) => i !== 2);
    const generic = new MarvellAttestationProvider();
    expect((await generic.verify({ attestation: await generic.read(realEvidence), intermediateCerts: pool })).status).toBe(true);
    expect((await verify(pool, realEvidence, bundledTrust)).status).toBe(false);
  });

  it.each([2, 3])("rejects a correctly owner-signed certificate with a mismatched key at role %i", async (index) => {
    const pool = [...certificates];
    pool[index] = await issue(index === 2 ? "Card" : "Partition", index === 2 ? other : card, "Owner", owner);
    expect((await verify(pool)).status).toBe(false);
  });

  it("requires issuer/subject matching in addition to a valid certificate signature", async () => {
    const pool = [...certificates];
    pool[1] = await issue("Partition", partition, "Different issuer", card);
    expect(await pool[1].verify({ publicKey: certificates[0].publicKey, signatureOnly: true }, crypto)).toBe(true);
    expect((await verify(pool)).status).toBe(false);
  });

  it("continues from an incomplete manufacturer combination to a complete one", async () => {
    const wrongCard = await issue("Other card", other, "Manufacturer", manufacturer);
    const wrongPartition = await issue("Other partition", partition, "Other card", other);
    expect(wrongCard.toString("hex") < certificates[0].toString("hex")).toBe(true);
    const results = await Promise.all([verify([wrongCard, wrongPartition, ...certificates]), verify([...certificates, wrongPartition, wrongCard])]);
    for (const result of results) {
      expect(result.status).toBe(true);
      expect(ids(result.chain!)).toEqual(ids([trust.manufacturerRoot, certificates[0], certificates[1]]));
    }
  });

  it("chooses the same complete proof for all bundle permutations", async () => {
    const expected = ids([trust.manufacturerRoot, certificates[0], certificates[1]]);
    const results = await Promise.all(permutations(certificates).map((pool) => verify(pool)));
    for (const result of results) {
      expect(result.status).toBe(true);
      expect(ids(result.chain!)).toEqual(expected);
    }
  });

  it("allows duplicate certificates, roots and unused certificates without mutating the pool", async () => {
    const unrelated = await issue("Unrelated", other, "Unrelated", other);
    const pool = [trust.manufacturerRoot, trust.ownerRoot, ...certificates, new x509.X509Certificate(certificates[0].rawData), unrelated];
    const original = [...pool];
    expect((await verify(pool)).status).toBe(true);
    expect(pool).toEqual(original);
  });

  it("allows equal card/partition keys when all four role certificates are distinct", async () => {
    const pool = [certificates[0], await issue("Partition", card, "Card", card), certificates[2], await issue("Partition", card, "Owner", owner)];
    expect((await verify(pool, await signedEvidence(card))).status).toBe(true);
    const missingOwnerPartition = [...pool.slice(0, 3), new x509.X509Certificate(pool[2].rawData)];
    expect((await verify(missingOwnerPartition, await signedEvidence(card))).status).toBe(false);
  });

  it("does not infer roles from CN text", async () => {
    const roots = { manufacturerRoot: await issue("Owner-looking", manufacturer, "Owner-looking", manufacturer), ownerRoot: await issue("Manufacturer-looking", owner, "Manufacturer-looking", owner) };
    const pool = [
      await issue("A", card, "Owner-looking", manufacturer),
      await issue("B", partition, "A", card),
      await issue("C", card, "Manufacturer-looking", owner),
      await issue("D", partition, "Manufacturer-looking", owner),
    ];
    expect((await verify(pool, evidence, roots)).status).toBe(true);
  });

  it("accepts self-issued key rollover when the required direct signatures are valid", async () => {
    const pool = [await issue("Manufacturer", card, "Manufacturer", manufacturer), await issue("Partition", partition, "Manufacturer", card), certificates[2], certificates[3]];
    expect(pool[0].subject).toBe(pool[0].issuer);
    expect(await pool[0].isSelfSigned(crypto)).toBe(false);
    expect((await verify(pool)).status).toBe(true);
  });

  it("rejects cycles with no correctly certified manufacturer card", async () => {
    const pool = [await issue("Card", card, "Partition", partition), certificates[1], certificates[2], certificates[3]];
    expect((await verify(pool)).status).toBe(false);
  });

  it("rejects an evidence signature from the card key instead of the partition key", async () => {
    expect((await verify(certificates, await signedEvidence(card))).status).toBe(false);
  });

  it("rejects a damaged evidence signature with the existing signature-error contract", async () => {
    const bytes = evidence.slice();
    bytes[bytes.length - 1] ^= 1;
    const result = await verify(certificates, bytes);
    expect(result.status).toBe(false);
    if (!result.status) expect(result.error.message).toBe("Failed to verify the attestation signature.");
  });

  it("bounds certificate count and DER bytes before searching", async () => {
    const oversized = await issue("Oversized", other, "Owner", owner, [new x509.Extension("1.2.3.4", false, new ArrayBuffer(1024 * 1024))]);
    const results = await Promise.all([verify(Array(65).fill(certificates[0])), verify([...certificates, oversized])]);
    expect(results.map((result) => result.status)).toEqual([false, false]);
    if (!results[0].status) expect(results[0].error.message).toMatch(/Too many certificates/);
    if (!results[1].status) expect(results[1].error.message).toMatch(/Certificate data exceeds/);
  });
});

describe("Google Cloud HSM key normalization", () => {
  let rsaOwner: CryptoKeyPair;
  let rsaTrust: GoogleCloudHsmTrust;
  let rsaPool: x509.X509Certificate[];

  beforeAll(async () => {
    rsaOwner = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
    rsaTrust = { manufacturerRoot: trust.manufacturerRoot, ownerRoot: await issue("RSA owner", rsaOwner, "RSA owner", rsaOwner) };
    rsaPool = [certificates[0], certificates[1], await issue("Card", card, "RSA owner", rsaOwner), await issue("Partition", partition, "RSA owner", rsaOwner)];
  });

  async function changedKey(cert: x509.X509Certificate, change: (asn: Certificate) => void): Promise<x509.X509Certificate> {
    const asn = AsnConvert.parse(cert.rawData, Certificate);
    change(asn);
    asn.signatureValue = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, rsaOwner.privateKey, AsnConvert.serialize(asn.tbsCertificate));
    return new x509.X509Certificate(AsnConvert.serialize(asn));
  }

  it("matches equivalent RSA SPKIs with NULL versus absent algorithm parameters", async () => {
    const alternate = await changedKey(rsaPool[2], (asn) => {
      asn.tbsCertificate.subjectPublicKeyInfo.algorithm.parameters = undefined;
    });
    expect(Buffer.from(alternate.publicKey.rawData).equals(Buffer.from(rsaPool[0].publicKey.rawData))).toBe(false);
    expect((await verify([rsaPool[0], rsaPool[1], alternate, rsaPool[3]], evidence, rsaTrust)).status).toBe(true);
  });

  it("does not strip RSA-PSS algorithm restrictions to make a key match", async () => {
    const pss = await changedKey(rsaPool[2], (asn) => {
      asn.tbsCertificate.subjectPublicKeyInfo.algorithm = new AlgorithmIdentifier({ algorithm: "1.2.840.113549.1.1.10" });
    });
    expect((await verify([rsaPool[0], rsaPool[1], pss, rsaPool[3]], evidence, rsaTrust)).status).toBe(false);
  });

  it("ignores an unused, owner-signed certificate with a malformed public key", async () => {
    const candidate = await issue("Malformed", other, "RSA owner", rsaOwner);
    const malformed = await changedKey(candidate, (asn) => {
      asn.tbsCertificate.subjectPublicKeyInfo.algorithm = new AlgorithmIdentifier({ algorithm: "1.2.840.113549.1.1.1" });
    });
    expect(() => malformed.publicKey).toThrow();
    expect((await verify([malformed, ...rsaPool], evidence, rsaTrust)).status).toBe(true);
  });
});

describe("Google Cloud HSM trust configuration", () => {
  it.each(["omitted", "undefined"])("keeps constructor role-bound roots for an %s override", async (mode) => {
    const provider = new MarvellAttestationProvider({ profile: "google-cloud-hsm", trustedCerts: trust });
    const result = await provider.verify({ attestation: await provider.read(evidence), intermediateCerts: certificates, ...(mode === "undefined" ? { trustedCerts: undefined } : {}) });
    expect(result.status).toBe(true);
  });

  it("replaces both constructor anchors per call while retaining the Google profile", async () => {
    const provider = new MarvellAttestationProvider({ profile: "google-cloud-hsm", trustedCerts: trust });
    const result = await provider.verify({ attestation: await provider.read(realEvidence), intermediateCerts: realCertificates, trustedCerts: bundledTrust });
    expect(result.status).toBe(true);
    expect(result.chain?.[0].equal(MANUFACTURER_ROOT_CERT)).toBe(true);
    expect((await provider.verify({ attestation: await provider.read(evidence), intermediateCerts: certificates })).status).toBe(true);
  });

  it("never falls back or disables Google checks after an override", async () => {
    const provider = new MarvellAttestationProvider({ profile: "google-cloud-hsm" });
    const attestation = await provider.read(realEvidence);
    expect((await provider.verify({ attestation, intermediateCerts: realCertificates, trustedCerts: trust })).status).toBe(false);
    expect((await provider.verify({ attestation, intermediateCerts: realCertificates.slice(0, 3), trustedCerts: bundledTrust })).status).toBe(false);
    expect((await provider.verify({ attestation, intermediateCerts: realCertificates })).status).toBe(true);
  });

  it("snapshots constructor and per-call role objects", async () => {
    const roots = { ...trust };
    const provider = new MarvellAttestationProvider({ profile: "google-cloud-hsm", trustedCerts: roots });
    Object.assign(roots, bundledTrust);
    const attestation = await provider.read(evidence);
    expect((await provider.verify({ attestation, intermediateCerts: certificates })).status).toBe(true);
    const override = { ...trust };
    const pending = new MarvellAttestationProvider({ profile: "google-cloud-hsm" }).verify({ attestation, intermediateCerts: certificates, trustedCerts: override });
    Object.assign(override, bundledTrust);
    expect((await pending).status).toBe(true);
  });

  it("isolates concurrent calls with different named trust pairs", async () => {
    const provider = new MarvellAttestationProvider({ profile: "google-cloud-hsm" });
    const a = await provider.read(realEvidence);
    const b = await provider.read(evidence);
    const results = await Promise.all([
      provider.verify({ attestation: b, intermediateCerts: certificates, trustedCerts: trust }),
      provider.verify({ attestation: a, intermediateCerts: realCertificates }),
      provider.verify({ attestation: a, intermediateCerts: realCertificates, trustedCerts: trust }),
    ]);
    expect(results.map((result) => result.status)).toEqual([true, true, false]);
  });

  it("preserves the configured Crypto for key normalization and certificate/evidence signatures", async () => {
    const customCrypto = new PeculiarCrypto() as unknown as Crypto;
    const exportKey = vi.spyOn(customCrypto.subtle, "exportKey");
    const signature = vi.spyOn(customCrypto.subtle, "verify");
    const provider = new MarvellAttestationProvider({ profile: "google-cloud-hsm", crypto: customCrypto });
    const result = await provider.verify({ attestation: await provider.read(evidence), intermediateCerts: certificates, trustedCerts: trust });
    expect(result.status).toBe(true);
    expect(exportKey).toHaveBeenCalledWith("spki", expect.anything());
    expect(signature).toHaveBeenCalledWith(expect.objectContaining({ name: "ECDSA" }), expect.anything(), expect.anything(), expect.anything());
    expect(signature).toHaveBeenCalledWith(expect.objectContaining({ name: "RSASSA-PKCS1-v1_5" }), expect.anything(), expect.anything(), expect.anything());
  });

  it.each([[], [MANUFACTURER_ROOT_CERT], [MANUFACTURER_ROOT_CERT, OWNER_ROOT_CERT], null, {}, { manufacturerRoot: MANUFACTURER_ROOT_CERT }])(
    "rejects ambiguous or incomplete trust input %#",
    async (input) => {
      const options = { profile: "google-cloud-hsm", trustedCerts: input } as unknown as MarvellAttestationProviderParams;
      expect(() => new MarvellAttestationProvider(options)).toThrow(TypeError);
      const provider = new MarvellAttestationProvider({ profile: "google-cloud-hsm" });
      const result = await provider.verify({ attestation: await provider.read(realEvidence), intermediateCerts: realCertificates, trustedCerts: input as GoogleCloudHsmTrust });
      expect(result.status).toBe(false);
    },
  );

  it("rejects anchors with the same key even when their DER and subjects differ", async () => {
    const duplicateKeyRoot = await issue("Another authority", manufacturer, "Another authority", manufacturer);
    expect(() => new MarvellAttestationProvider({ profile: "google-cloud-hsm", trustedCerts: { manufacturerRoot: trust.manufacturerRoot, ownerRoot: duplicateKeyRoot } })).toThrow(/independent/);
  });

  it("rejects named trust in the generic profile and unknown profiles without fallback", async () => {
    expect(() => new MarvellAttestationProvider({ profile: "automatic" } as unknown as MarvellAttestationProviderParams)).toThrow(/profile/);
    expect(() => new MarvellAttestationProvider({ trustedCerts: trust } as unknown as MarvellAttestationProviderParams)).toThrow(/array/);
    const provider = new MarvellAttestationProvider();
    expect((await provider.verify({ attestation: await provider.read(realEvidence), intermediateCerts: realCertificates, trustedCerts: bundledTrust })).status).toBe(false);
  });
});
