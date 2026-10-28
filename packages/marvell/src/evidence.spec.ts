import { beforeAll, describe, expect, expectTypeOf, it, vi } from "vitest";
import { gzipSync, gunzipSync } from "node:zlib";
import * as x509 from "@peculiar/x509";
import { Crypto as PeculiarCrypto } from "@peculiar/webcrypto";
import type { Attestation, AttestationProvider } from "@peculiar/attestation-common";
import { MarvellAttestationProvider, type GoogleCloudHsmTrust, type MarvellAttestationType, type MarvellEvidenceVerificationParams } from "./index";
import { CryptokiKeyType, MarvellAttributeType } from "./attestation";
import { base64CompressedData, certChain } from "../test/fixtures";

type Profile = "generic" | "google-cloud-hsm";
type WireAttribute = [MarvellAttributeType, Uint8Array];
const profiles: Profile[] = ["generic", "google-cloud-hsm"];
let trust: GoogleCloudHsmTrust;
let certificates: x509.X509Certificate[];
let partition: CryptoKeyPair;
let rsa: CryptoKeyPair;
let ec: CryptoKeyPair;
let supported: Record<"RSA" | "EC", Uint8Array<ArrayBuffer>>;
let unsupported: Record<string, Uint8Array<ArrayBuffer>>;

const byte = (value: number): Uint8Array => new Uint8Array([value]);
function uint32(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value);
  return bytes;
}

async function issue(subject: string, publicKey: CryptoKey, issuer: string, keys: CryptoKeyPair): Promise<x509.X509Certificate> {
  return x509.X509CertificateGenerator.create(
    {
      subject,
      issuer,
      publicKey,
      signingKey: keys.privateKey,
      signingAlgorithm: { name: keys.privateKey.algorithm.name, hash: "SHA-256" },
      notBefore: new Date("2024-01-01"),
      notAfter: new Date("2099-01-01"),
    },
    crypto,
  );
}

/** Build an actual wire container and sign its header and attributes, rather than changing parsed metadata. */
async function signedEvidence(attributes: WireAttribute[]): Promise<Uint8Array<ArrayBuffer>> {
  const chunks = attributes.map(([tag, value]) => Buffer.concat([uint32(tag), uint32(value.length), value]));
  const object = Buffer.concat([uint32(1), uint32(attributes.length), uint32(12 + chunks.reduce((size, chunk) => size + chunk.length, 0)), ...chunks]);
  const info = Buffer.alloc(8);
  info.writeUInt16BE(1, 0);
  info.writeUInt16BE(3, 2);
  info.writeUInt16BE(8, 4);
  const body = Buffer.concat([info, object]);
  const template = gunzipSync(Buffer.from(base64CompressedData, "base64"));
  const prefix = Buffer.from(template.subarray(0, template.length - 256 - template.readUInt32BE(12)));
  prefix.writeUInt32BE(prefix.length + body.length + 256, 8);
  prefix.writeUInt32BE(body.length, 12);
  const signedData = Buffer.concat([prefix, body]);
  const signature = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, partition.privateKey, signedData);
  return Uint8Array.from(Buffer.concat([signedData, new Uint8Array(signature)]));
}

function provider(profile: Profile): MarvellAttestationProvider {
  return profile === "generic" ? new MarvellAttestationProvider({ trustedCerts: [trust.manufacturerRoot, trust.ownerRoot] }) : new MarvellAttestationProvider({ profile, trustedCerts: trust });
}

function roots(profile: Profile): NonNullable<MarvellEvidenceVerificationParams["trustedCerts"]> {
  return profile === "generic" ? [trust.manufacturerRoot, trust.ownerRoot] : { ...trust };
}

beforeAll(async () => {
  const ecdsa = { name: "ECDSA", namedCurve: "P-256" };
  const rsassa = { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
  const [manufacturer, owner, card, ecKey, partitionKey, rsaKey] = await Promise.all([
    crypto.subtle.generateKey(ecdsa, true, ["sign", "verify"]),
    crypto.subtle.generateKey(ecdsa, true, ["sign", "verify"]),
    crypto.subtle.generateKey(ecdsa, true, ["sign", "verify"]),
    crypto.subtle.generateKey(ecdsa, true, ["sign", "verify"]),
    crypto.subtle.generateKey(rsassa, true, ["sign", "verify"]),
    crypto.subtle.generateKey(rsassa, true, ["sign", "verify"]),
  ]);
  ec = ecKey;
  partition = partitionKey;
  rsa = rsaKey;
  trust = { manufacturerRoot: await issue("CN=Manufacturer", manufacturer.publicKey, "CN=Manufacturer", manufacturer), ownerRoot: await issue("CN=Owner", owner.publicKey, "CN=Owner", owner) };
  certificates = [
    await issue("CN=Card", card.publicKey, "CN=Manufacturer", manufacturer),
    await issue("CN=Partition", partition.publicKey, "CN=Card", card),
    await issue("CN=Card", card.publicKey, "CN=Owner", owner),
    await issue("CN=Partition", partition.publicKey, "CN=Owner", owner),
  ];
  const jwk = await crypto.subtle.exportKey("jwk", rsa.publicKey);
  const point = new Uint8Array(await crypto.subtle.exportKey("raw", ec.publicKey));
  supported = {
    RSA: await signedEvidence([
      [MarvellAttributeType.OBJ_ATTR_KEY_TYPE, byte(CryptokiKeyType.CKK_RSA)],
      [MarvellAttributeType.OBJ_ATTR_VERIFY, byte(1)],
      [MarvellAttributeType.OBJ_ATTR_MODULUS, Buffer.from(jwk.n!, "base64url")],
      [MarvellAttributeType.OBJ_ATTR_PUBLIC_EXPONENT, Buffer.from(jwk.e!, "base64url")],
    ]),
    EC: await signedEvidence([
      [MarvellAttributeType.OBJ_ATTR_KEY_TYPE, byte(CryptokiKeyType.CKK_EC)],
      [MarvellAttributeType.OBJ_ATTR_VERIFY, byte(1)],
      [MarvellAttributeType.OBJ_ATTR_VALUE_LEN, uint32(point.length)],
      [MarvellAttributeType.OBJ_ATTR_MODULUS, point],
    ]),
  };
  unsupported = {
    AES: await signedEvidence([
      [MarvellAttributeType.OBJ_ATTR_CLASS, byte(4)],
      [MarvellAttributeType.OBJ_ATTR_KEY_TYPE, byte(CryptokiKeyType.CKK_AES)],
      [MarvellAttributeType.OBJ_ATTR_VALUE_LEN, uint32(32)],
    ]),
    DSA: await signedEvidence([[MarvellAttributeType.OBJ_ATTR_KEY_TYPE, byte(CryptokiKeyType.CKK_DSA)]]),
    incompleteEC: await signedEvidence([
      [MarvellAttributeType.OBJ_ATTR_KEY_TYPE, byte(CryptokiKeyType.CKK_EC)],
      [MarvellAttributeType.OBJ_ATTR_VERIFY, byte(1)],
    ]),
  };
});

it("preserves shared provider and required-publicKey read types", async () => {
  expectTypeOf<MarvellAttestationProvider>().toExtend<AttestationProvider>();
  expectTypeOf<Awaited<ReturnType<MarvellAttestationProvider["read"]>>>().toEqualTypeOf<MarvellAttestationType>();
  const shared: AttestationProvider = new MarvellAttestationProvider();
  const attestation: Attestation = await shared.read(Buffer.from(base64CompressedData, "base64"));
  expect(attestation.publicKey).toBeInstanceOf(x509.PublicKey);
  const certs = x509.PemConverter.decode(certChain).map((cert) => new x509.X509Certificate(cert));
  expect((await shared.verify({ attestation, intermediateCerts: certs })).status).toBe(true);
});

describe.each(profiles)("Marvell evidence API (%s)", (profile) => {
  it.each(["AES", "DSA", "incompleteEC"])("verifies signed %s evidence independently of extraction errors", async (kind) => {
    const instance = provider(profile);
    const bytes = unsupported[kind];
    const evidence = instance.parse(bytes);
    expect(evidence.signedData.length + evidence.signature.length).toBe(bytes.length);
    const message = kind === "incompleteEC" ? "Unsupported curve" : "Unsupported key type";
    expect(() => instance.extractPublicKey(evidence)).toThrow(message);
    await expect(instance.read(bytes)).rejects.toThrow(message);
    const results = await Promise.all([instance.verifyEvidence({ evidence, intermediateCerts: certificates }), instance.verifyEvidence({ evidence: bytes, intermediateCerts: certificates })]);
    for (const result of results) {
      expect(result.status).toBe(true);
      expect(result.signer?.publicKey.equal(certificates[1].publicKey)).toBe(true);
      expect(result.chain?.[0].equal(trust.manufacturerRoot)).toBe(true);
    }
  });

  it.each(["RSA", "EC"] as const)("keeps %s extraction and legacy read/verify working", async (kind) => {
    const instance = provider(profile);
    const parsed = instance.parse(supported[kind]);
    const extracted = instance.extractPublicKey(parsed);
    const legacy = await instance.read(supported[kind]);
    const expected = (kind === "RSA" ? rsa : ec).publicKey;
    const imported = await extracted.export({ ...expected.algorithm, hash: "SHA-256" }, ["verify"], crypto);
    expect(await crypto.subtle.exportKey("spki", imported)).toEqual(await crypto.subtle.exportKey("spki", expected));
    expect(legacy.publicKey.equal(extracted)).toBe(true);
    expect(legacy.metadata).toEqual(parsed);
    const results = await Promise.all([instance.verify({ attestation: legacy, intermediateCerts: certificates }), instance.verifyEvidence({ evidence: parsed, intermediateCerts: certificates })]);
    expect(results.map((result) => result.status)).toEqual([true, true]);
  });

  it("does not call extraction during parsing or either evidence-verification path", async () => {
    const instance = provider(profile);
    const extract = vi.spyOn(instance, "extractPublicKey").mockImplementation(() => {
      throw new Error("Extraction must be independent");
    });
    const parsed = instance.parse(unsupported.AES);
    expect((await instance.verifyEvidence({ evidence: parsed, intermediateCerts: certificates })).status).toBe(true);
    expect((await instance.verifyEvidence({ evidence: unsupported.AES, intermediateCerts: certificates })).status).toBe(true);
    expect(extract).not.toHaveBeenCalled();
  });

  it.each(["ArrayBuffer", "offset Uint8Array", "offset DataView", "gzip"])("accepts %s input without extraction", async (kind) => {
    const bytes = unsupported.AES;
    const padded = new Uint8Array(bytes.length + 10);
    padded.set(bytes, 4);
    const inputs: Record<string, BufferSource> = {
      ArrayBuffer: bytes.buffer.slice(0),
      "offset Uint8Array": padded.subarray(4, 4 + bytes.length),
      "offset DataView": new DataView(padded.buffer, 4, bytes.length),
      gzip: Uint8Array.from(gzipSync(bytes)),
    };
    const instance = provider(profile);
    const parsed = instance.parse(inputs[kind]);
    expect(parsed.attestationData.firstKey.attributes.OBJ_ATTR_KEY_TYPE).toBe("CKK_AES");
    expect(parsed.compressed).toBe(kind === "gzip");
    expect((await instance.verifyEvidence({ evidence: inputs[kind], intermediateCerts: certificates })).status).toBe(true);
  });

  it.each(["signature", "signed attribute"])("rejects a changed %s independently of a key-extraction error", async (changed) => {
    const bytes = unsupported.AES.slice();
    bytes[bytes.length - (changed === "signature" ? 1 : 257)] ^= 1;
    const instance = provider(profile);
    const result = await instance.verifyEvidence({ evidence: bytes, intermediateCerts: certificates });
    expect(result.status).toBe(false);
    if (!result.status) expect(result.error.message).toBe("Failed to verify the attestation signature.");
    expect(() => instance.extractPublicKey(instance.parse(bytes))).toThrow("Unsupported key type");
  });

  it.each(["empty", "truncated", "invalid gzip"])("throws on %s parsing but returns a failed raw verification result", async (kind) => {
    const inputs: Record<string, Uint8Array> = { empty: new Uint8Array(0), truncated: unsupported.AES.subarray(0, 12), "invalid gzip": new Uint8Array([0x1f, 0x8b, 0xff]) };
    const instance = provider(profile);
    expect(() => instance.parse(inputs[kind] as BufferSource)).toThrow();
    await expect(instance.read(inputs[kind] as BufferSource)).rejects.toThrow();
    await expect(instance.verifyEvidence({ evidence: inputs[kind] as BufferSource, intermediateCerts: certificates })).resolves.toMatchObject({ status: false, error: expect.any(Error) });
  });

  it("retains per-call trust replacement, snapshots and isolation without fallback", async () => {
    const instance = new MarvellAttestationProvider({ profile });
    const override = roots(profile);
    const pending = instance.verifyEvidence({ evidence: unsupported.AES, intermediateCerts: certificates, trustedCerts: override });
    if (Array.isArray(override)) override.length = 0;
    else Object.assign(override, { manufacturerRoot: trust.ownerRoot, ownerRoot: trust.manufacturerRoot });
    expect((await pending).status).toBe(true);
    const results = await Promise.all([
      instance.verifyEvidence({ evidence: unsupported.AES, intermediateCerts: certificates, trustedCerts: roots(profile) }),
      instance.verifyEvidence({ evidence: instance.parse(unsupported.AES), intermediateCerts: certificates }),
      instance.verifyEvidence({ evidence: unsupported.AES, intermediateCerts: certificates, trustedCerts: [] }),
    ]);
    expect(results.map((result) => result.status)).toEqual([true, false, false]);
  });

  it("preserves the configured Crypto with per-call trust", async () => {
    const customCrypto = new PeculiarCrypto() as unknown as Crypto;
    const signature = vi.spyOn(customCrypto.subtle, "verify");
    const instance = new MarvellAttestationProvider({ profile, crypto: customCrypto });
    const result = await instance.verifyEvidence({ evidence: unsupported.DSA, intermediateCerts: certificates, trustedCerts: roots(profile) });
    expect(result.status).toBe(true);
    expect(signature).toHaveBeenCalledWith(expect.objectContaining({ name: "RSASSA-PKCS1-v1_5" }), expect.anything(), expect.anything(), expect.anything());
    expect(signature).toHaveBeenCalledWith(expect.objectContaining({ name: "ECDSA" }), expect.anything(), expect.anything(), expect.anything());
  });
});

it("keeps the selected Google policy when a named override is passed to verifyEvidence", async () => {
  const withoutOwnerPartition = certificates.slice(0, 3);
  const generic = new MarvellAttestationProvider();
  const google = new MarvellAttestationProvider({ profile: "google-cloud-hsm" });
  const results = await Promise.all([
    generic.verifyEvidence({ evidence: unsupported.AES, intermediateCerts: withoutOwnerPartition, trustedCerts: roots("generic") }),
    google.verifyEvidence({ evidence: unsupported.AES, intermediateCerts: withoutOwnerPartition, trustedCerts: roots("google-cloud-hsm") }),
  ]);
  expect(results.map((result) => result.status)).toEqual([true, false]);
});
