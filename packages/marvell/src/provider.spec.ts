import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import * as zlib from "node:zlib";
import * as x509 from "@peculiar/x509";
import { Crypto as PeculiarCrypto } from "@peculiar/webcrypto";
import { MarvellAttestationProvider, type MarvellAttestationType } from "./provider";
import { MANUFACTURER_ROOT_CERT, OWNER_ROOT_CERT } from "./certs";
import { base64CompressedData, certChain } from "../test/fixtures";

const rootsA = [MANUFACTURER_ROOT_CERT, OWNER_ROOT_CERT];
let rootsB: x509.X509Certificate[];
let certsA: x509.X509Certificate[];
let certsB: x509.X509Certificate[];
let attestationA: MarvellAttestationType;
let attestationB: MarvellAttestationType;

beforeAll(async () => {
  const provider = new MarvellAttestationProvider();
  certsA = x509.PemConverter.decode(certChain).map((cert) => new x509.X509Certificate(cert));
  attestationA = await provider.read(Buffer.from(base64CompressedData, "base64"));
  const keys = await Promise.all(Array.from({ length: 2 }, () => crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])));
  const signer = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pairs = await Promise.all(
    keys.map(async (rootKeys, index) => {
      const name = `CN=Custom root ${index}`;
      const validity = { notBefore: new Date("2024-01-01T00:00:00Z"), notAfter: new Date("2099-01-01T00:00:00Z") };
      return Promise.all([
        x509.X509CertificateGenerator.createSelfSigned({ name, keys: rootKeys, signingAlgorithm: { name: "ECDSA", hash: "SHA-256" }, ...validity }, crypto),
        x509.X509CertificateGenerator.create(
          { subject: "CN=Custom partition", issuer: name, publicKey: signer.publicKey, signingKey: rootKeys.privateKey, signingAlgorithm: { name: "ECDSA", hash: "SHA-256" }, ...validity },
          crypto,
        ),
      ]);
    }),
  );
  rootsB = pairs.map(([root]) => root);
  certsB = pairs.map(([, cert]) => cert);
  const evidence = new Uint8Array(zlib.gunzipSync(Buffer.from(base64CompressedData, "base64")));
  const signature = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, signer.privateKey, evidence.subarray(0, -256));
  evidence.set(new Uint8Array(signature), evidence.length - 256);
  attestationB = await provider.read(evidence);
});

afterEach(() => vi.restoreAllMocks());

describe("MarvellAttestationProvider: per-call trust", () => {
  it.each(["omitted", "undefined"])("uses bundled roots when the override is %s", async (mode) => {
    const provider = new MarvellAttestationProvider();
    const result = await provider.verify({ attestation: attestationA, intermediateCerts: certsA, ...(mode === "undefined" ? { trustedCerts: undefined } : {}) });
    expect(result.status).toBe(true);
    expect(result.chain?.[0].equal(MANUFACTURER_ROOT_CERT)).toBe(true);
  });

  it.each(["omitted", "undefined"])("uses constructor roots when the override is %s", async (mode) => {
    const provider = new MarvellAttestationProvider({ trustedCerts: rootsB });
    const result = await provider.verify({ attestation: attestationB, intermediateCerts: certsB, ...(mode === "undefined" ? { trustedCerts: undefined } : {}) });
    expect(result.status).toBe(true);
    expect(result.chain?.[0].equal(rootsB[0])).toBe(true);
    expect((await provider.verify({ attestation: attestationA, intermediateCerts: certsA })).status).toBe(false);
  });

  it("replaces bundled roots with a valid custom set", async () => {
    const provider = new MarvellAttestationProvider();
    expect((await provider.verify({ attestation: attestationB, intermediateCerts: certsB })).status).toBe(false);
    const result = await provider.verify({ attestation: attestationB, intermediateCerts: certsB, trustedCerts: rootsB });
    expect(result.status).toBe(true);
    expect(result.chain?.[0].equal(rootsB[0])).toBe(true);
  });

  it("replaces constructor roots completely instead of merging them", async () => {
    const provider = new MarvellAttestationProvider({ trustedCerts: rootsB });
    const result = await provider.verify({ attestation: attestationA, intermediateCerts: certsA, trustedCerts: rootsA });
    expect(result.status).toBe(true);
    expect(result.chain?.[0].equal(rootsA[0])).toBe(true);
  });

  it("does not fall back to bundled or constructor roots after an unsuccessful override", async () => {
    const results = await Promise.all(
      [new MarvellAttestationProvider(), new MarvellAttestationProvider({ trustedCerts: rootsA })].map((provider) =>
        provider.verify({ attestation: attestationA, intermediateCerts: certsA, trustedCerts: rootsB }),
      ),
    );
    expect(results.map((result) => result.status)).toEqual([false, false]);
  });

  it.each([0, 1])("returns a structured failure for an explicit %i-anchor override", async (count) => {
    const provider = new MarvellAttestationProvider({ trustedCerts: rootsA });
    const pending = provider.verify({ attestation: attestationA, intermediateCerts: certsA, trustedCerts: rootsB.slice(0, count) });
    await expect(pending).resolves.toMatchObject({ status: false, error: expect.any(Error) });
    const result = await pending;
    if (!result.status) expect(result.error.message).toMatch(/At least two certificates/);
  });

  it("rejects a malformed JavaScript override without using defaults", async () => {
    const result = await new MarvellAttestationProvider().verify({ attestation: attestationA, intermediateCerts: certsA, trustedCerts: null as unknown as x509.X509Certificate[] });
    expect(result.status).toBe(false);
  });

  it("preserves defaults after both a successful and a failed override", async () => {
    const provider = new MarvellAttestationProvider({ trustedCerts: rootsA });
    expect((await provider.verify({ attestation: attestationB, intermediateCerts: certsB, trustedCerts: rootsB })).status).toBe(true);
    expect((await provider.verify({ attestation: attestationA, intermediateCerts: certsA, trustedCerts: rootsB })).status).toBe(false);
    expect((await provider.verify({ attestation: attestationA, intermediateCerts: certsA })).status).toBe(true);
  });

  it("isolates concurrent requests with different trust sets", async () => {
    const provider = new MarvellAttestationProvider({ trustedCerts: rootsA });
    const results = await Promise.all([
      provider.verify({ attestation: attestationB, intermediateCerts: certsB, trustedCerts: rootsB }),
      provider.verify({ attestation: attestationA, intermediateCerts: certsA }),
      provider.verify({ attestation: attestationA, intermediateCerts: certsA, trustedCerts: rootsB }),
      provider.verify({ attestation: attestationB, intermediateCerts: certsB, trustedCerts: rootsB }),
    ]);
    expect(results.map((result) => result.status)).toEqual([true, true, false, true]);
  });

  it("uses the configured WebCrypto provider for overrides", async () => {
    const customCrypto = new PeculiarCrypto() as unknown as Crypto;
    const verify = vi.spyOn(customCrypto.subtle, "verify");
    const provider = new MarvellAttestationProvider({ crypto: customCrypto });
    const result = await provider.verify({ attestation: attestationB, intermediateCerts: certsB, trustedCerts: rootsB });
    expect(result.status).toBe(true);
    expect(verify).toHaveBeenCalledWith(expect.objectContaining({ name: "RSASSA-PKCS1-v1_5" }), expect.anything(), expect.anything(), expect.anything());
    expect(verify).toHaveBeenCalledWith(expect.objectContaining({ name: "ECDSA" }), expect.anything(), expect.anything(), expect.anything());
  });

  it("snapshots constructor roots instead of retaining the caller's mutable array", async () => {
    const trustedCerts = [...rootsB];
    const provider = new MarvellAttestationProvider({ trustedCerts });
    trustedCerts.splice(0, trustedCerts.length, ...rootsA);
    expect((await provider.verify({ attestation: attestationB, intermediateCerts: certsB })).status).toBe(true);
  });

  it("snapshots per-call roots before asynchronous verification", async () => {
    const trustedCerts = [...rootsB];
    const pending = new MarvellAttestationProvider().verify({ attestation: attestationB, intermediateCerts: certsB, trustedCerts });
    trustedCerts.splice(0, trustedCerts.length, ...rootsA);
    expect((await pending).status).toBe(true);
  });

  it.each([0, 1])("retains immediate constructor rejection for %i anchors", (count) => {
    expect(() => new MarvellAttestationProvider({ trustedCerts: rootsA.slice(0, count) })).toThrow(/At least two certificates/);
  });

  it("retains format rejection before considering the trust override", async () => {
    const result = await new MarvellAttestationProvider().verify({ attestation: { ...attestationA, format: "piv" }, intermediateCerts: certsA, trustedCerts: [] });
    expect(result.status).toBe(false);
    if (!result.status) expect(result.error.message).toBe("Invalid attestation format");
  });
});
