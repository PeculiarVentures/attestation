import { beforeAll, describe, expect, it, vi } from "vitest";
import * as x509 from "@peculiar/x509";
import { PivAttestationProvider } from "./provider";
import { YUBICO_ROOT_CERT, YUBICO_INTERMEDIATE_CERTS } from "./certs";

const provider = new PivAttestationProvider();

// Generated certificates exercise full device/slot chains without hardware or network.
// Official production CA signatures and trust anchors are tested separately below.
interface TestChain {
  root: x509.X509Certificate;
  intermediates: x509.X509Certificate[];
  leaf: x509.X509Certificate;
}

async function createChain(names: string[]): Promise<TestChain> {
  const keys = await Promise.all(names.map(() => crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])));
  const certs = await Promise.all(
    names.map(async (name, i) => {
      const issuer = Math.max(0, i - 1);
      return x509.X509CertificateGenerator.create({
        subject: `CN=${name}`,
        issuer: `CN=${names[issuer]}`,
        publicKey: keys[i].publicKey,
        signingKey: keys[issuer].privateKey,
        signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
        notBefore: new Date("2024-01-01T00:00:00Z"),
        notAfter: new Date("2099-01-01T00:00:00Z"),
        extensions: [
          new x509.BasicConstraintsExtension(i < names.length - 1, undefined, true),
          new x509.KeyUsagesExtension(i < names.length - 1 ? x509.KeyUsageFlags.keyCertSign : x509.KeyUsageFlags.digitalSignature, true),
          await x509.SubjectKeyIdentifierExtension.create(keys[i].publicKey),
          await x509.AuthorityKeyIdentifierExtension.create(keys[issuer].publicKey),
        ],
      });
    }),
  );
  return { root: certs[0], intermediates: certs.slice(1, -1), leaf: certs[certs.length - 1] };
}

let legacy: TestChain;
let modern: TestChain;

beforeAll(async () => {
  legacy = await createChain(["Test legacy PIV root", "YubiKey PIV Attestation", "YubiKey PIV Attestation 9a"]);
  modern = await createChain(["Test attestation root", "Test attestation intermediate", "Test PIV CA", "YubiKey PIV Attestation", "YubiKey PIV Attestation 9a"]);
});

describe("PivAttestationProvider: default certificates", () => {
  it("preserves the legacy root API and returns both official production roots", async () => {
    const roots = provider.getDefaultRootCerts();
    expect(provider.getDefaultRootCert()).toBe(YUBICO_ROOT_CERT);
    expect(roots[0]).toBe(provider.getDefaultRootCert());
    expect(roots.map((cert) => cert.subject)).toEqual(["CN=Yubico PIV Root CA Serial 263751", "CN=Yubico Attestation Root 1"]);
    expect(Buffer.from(await roots[1].getThumbprint("SHA-256")).toString("hex")).toBe("62760c6a6ef91679f454c8902b80fd009825b3f25da90f1fbace2ec6586cd5a8");
    expect(await Promise.all(roots.map((root) => root.isSelfSigned()))).toEqual([true, true]);
  });

  it("returns a fresh array so callers can extend the trust store safely", () => {
    const roots = provider.getDefaultRootCerts();
    roots.pop();
    roots.push(...YUBICO_INTERMEDIATE_CERTS);
    expect(provider.getDefaultRootCerts()).toHaveLength(2);
  });

  it.each(["A 1", "B 1", "B2 1"])("builds the official PIV %s CA chain to the new default root offline", async (suffix) => {
    const cert = YUBICO_INTERMEDIATE_CERTS.find((item) => item.subject === `CN=Yubico PIV Attestation ${suffix}`)!;
    const result = await provider.verify({ attestation: await provider.read(cert.rawData), intermediateCerts: [] });
    expect(result.status).toBe(true);
    expect(result.chain?.map((item) => item.subject)).toEqual([cert.subject, `CN=Yubico Attestation Intermediate ${suffix[0]} 1`, "CN=Yubico Attestation Root 1"]);
    expect(result.signer?.equal(cert)).toBe(true);
  });

  it.each([
    { name: "empty", trustedCerts: [] },
    { name: "legacy only", trustedCerts: [YUBICO_ROOT_CERT] },
  ])("does not implicitly trust the new root or bundled intermediates with an explicit $name trust store", async ({ trustedCerts }) => {
    const cert = YUBICO_INTERMEDIATE_CERTS.find((item) => item.subject === "CN=Yubico PIV Attestation B 1")!;
    const result = await provider.verify({ attestation: await provider.read(cert.rawData), intermediateCerts: [], trustedCerts });
    expect(result.status).toBe(false);
    expect(result.chain).toHaveLength(2);
  });

  it("accepts an explicitly pinned PIV CA even when its issuer is bundled", async () => {
    const cert = YUBICO_INTERMEDIATE_CERTS.find((item) => item.subject === "CN=Yubico PIV Attestation B 1")!;
    const result = await provider.verify({ attestation: await provider.read(cert.rawData), intermediateCerts: [], trustedCerts: [cert] });
    expect(result.status).toBe(true);
    expect(result.chain).toEqual([cert]);
  });

  it("ends the verified chain at the first explicitly trusted issuer", async () => {
    const cert = YUBICO_INTERMEDIATE_CERTS.find((item) => item.subject === "CN=Yubico PIV Attestation B 1")!;
    const issuer = YUBICO_INTERMEDIATE_CERTS.find((item) => item.subject === "CN=Yubico Attestation Intermediate B 1")!;
    const result = await provider.verify({
      attestation: await provider.read(cert.rawData),
      intermediateCerts: [],
      trustedCerts: [...provider.getDefaultRootCerts(), issuer],
    });
    expect(result.status).toBe(true);
    expect(result.chain).toEqual([cert, issuer]);
  });
});

describe("PivAttestationProvider: device chains", () => {
  it.each(["legacy", "modern"])("verifies a complete %s slot attestation using the default-root accessor", async (kind) => {
    const chain = kind === "legacy" ? legacy : modern;
    const instance = new PivAttestationProvider();
    vi.spyOn(instance, "getDefaultRootCerts").mockReturnValue([legacy.root, modern.root]);
    const attestation = await instance.read(chain.leaf.rawData);
    const intermediateCerts = [...chain.intermediates].reverse();
    const result = await instance.verify({ attestation, intermediateCerts });
    expect(result.status).toBe(true);
    expect(result.chain).toEqual([chain.leaf, ...[...chain.intermediates].reverse(), chain.root]);
    expect(result.signer).toEqual(chain.leaf);
    expect(attestation.format).toBe("piv");
    expect(attestation.publicKey.rawData).toEqual(chain.leaf.publicKey.rawData);
    expect(intermediateCerts).toHaveLength(chain.intermediates.length);
  });

  it("allows callers to extend the default trust store with custom roots", async () => {
    const result = await provider.verify({
      attestation: await provider.read(modern.leaf.rawData),
      intermediateCerts: modern.intermediates,
      trustedCerts: [...provider.getDefaultRootCerts(), modern.root],
    });
    expect(result.status).toBe(true);
    expect(result.chain).toHaveLength(5);
  });

  it("allows callers to replace the default trust store with a custom root", async () => {
    const trustedCerts = [legacy.root];
    const result = await provider.verify({ attestation: await provider.read(legacy.leaf.rawData), intermediateCerts: legacy.intermediates, trustedCerts });
    expect(result.status).toBe(true);
    expect(result.chain).toHaveLength(3);
    expect(trustedCerts).toEqual([legacy.root]);
  });

  it("accepts a pinned device f9 certificate with its issuing CA certificates present", async () => {
    const deviceCert = modern.intermediates[modern.intermediates.length - 1];
    const result = await provider.verify({
      attestation: await provider.read(modern.leaf.rawData),
      intermediateCerts: modern.intermediates,
      trustedCerts: [modern.root, deviceCert],
    });
    expect(result.status).toBe(true);
    expect(result.chain).toEqual([modern.leaf, deviceCert]);
  });

  it("rejects a complete chain to an untrusted root even when it is supplied as an intermediate", async () => {
    const result = await provider.verify({ attestation: await provider.read(modern.leaf.rawData), intermediateCerts: [modern.root, ...modern.intermediates] });
    expect(result.status).toBe(false);
    expect(result.chain).toHaveLength(5);
  });

  it("rejects an incomplete device chain", async () => {
    const result = await provider.verify({ attestation: await provider.read(modern.leaf.rawData), intermediateCerts: modern.intermediates.slice(0, -1), trustedCerts: [modern.root] });
    expect(result.status).toBe(false);
    expect(result.chain).toHaveLength(1);
  });

  it("rejects a corrupted attestation signature", async () => {
    const raw = new Uint8Array(modern.leaf.rawData.slice(0));
    raw[raw.length - 1] ^= 0xff;
    const result = await provider.verify({ attestation: await provider.read(raw), intermediateCerts: modern.intermediates, trustedCerts: [modern.root] });
    expect(result.status).toBe(false);
    expect(result.chain).toHaveLength(1);
  });

  it("rejects a same-subject issuer with a different signing key", async () => {
    const result = await provider.verify({ attestation: await provider.read(modern.leaf.rawData), intermediateCerts: legacy.intermediates, trustedCerts: [legacy.root, modern.root] });
    expect(result.status).toBe(false);
    expect(result.chain).toHaveLength(1);
  });
});
