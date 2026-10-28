import { beforeAll, describe, expect, it } from "vitest";
import * as zlib from "node:zlib";
import * as x509 from "@peculiar/x509";
import { AsnConvert } from "@peculiar/asn1-schema";
import { AlgorithmIdentifier, Certificate } from "@peculiar/asn1-x509";
import { Crypto as PeculiarCrypto } from "@peculiar/webcrypto";
import { MarvellAttestationValidator } from "./validator";
import { MANUFACTURER_ROOT_CERT, OWNER_ROOT_CERT } from "./certs";

import { base64CompressedData, certChain } from "../test/fixtures";

describe("Marvell:Validator", () => {
  it("should correctly validate the attestation data", async () => {
    const validator = new MarvellAttestationValidator();
    const data = Buffer.from(base64CompressedData, "base64");
    const pemChain = x509.PemConverter.decode(certChain);
    const certs = pemChain.map((cert) => {
      return new x509.X509Certificate(cert);
    });
    const result = await validator.validate(data, certs);
    expect(result.status).toBe(true);
    expect(result.signer?.subjectName.getField("CN")[0]).toBe("HSM:5.3G1953-ICM001225:PARTN:1, for FIPS mode");
    expect(result.chain).toHaveLength(3);
  });

  it("validates attestations using @peculiar/webcrypto", async () => {
    const validator = new MarvellAttestationValidator({ crypto: new PeculiarCrypto() as unknown as Crypto });
    const data = Buffer.from(base64CompressedData, "base64");
    const certs = x509.PemConverter.decode(certChain).map((cert) => new x509.X509Certificate(cert));

    const result = await validator.validate(data, certs);
    expect(result.status).toBe(true);
    expect(result.chain).toHaveLength(3);

    const corrupted = zlib.gunzipSync(data);
    corrupted[corrupted.length - 1] ^= 0xff;
    expect((await validator.validate(corrupted, certs)).status).toBe(false);
  });

  it("should fail validation with corrupted signature", async () => {
    const validator = new MarvellAttestationValidator();
    const data = Buffer.from(base64CompressedData, "base64");
    const unpackedData = zlib.gunzipSync(data);

    // Corrupt the data by modifying a byte
    const corruptedData = unpackedData;
    corruptedData[corruptedData.length - 1] ^= 0xff; // Flip the last byte

    const pemChain = x509.PemConverter.decode(certChain);
    const certs = pemChain.map((cert) => {
      return new x509.X509Certificate(cert);
    });
    const result = await validator.validate(corruptedData, certs);
    expect(result.status).toBe(false);
  });

  it("should throw an error if initialized with a single trusted certificate", () => {
    expect(
      () =>
        new MarvellAttestationValidator({
          trustedCerts: [OWNER_ROOT_CERT],
        }),
    ).toThrow();
  });
});

function fixtureCertificates(): x509.X509Certificate[] {
  return x509.PemConverter.decode(certChain).map((cert) => new x509.X509Certificate(cert));
}

function damagedSignature(cert: x509.X509Certificate): x509.X509Certificate {
  const bytes = new Uint8Array(cert.rawData.slice(0));
  let index = bytes.length - 1;
  while (!bytes[index]) index--;
  bytes[index]--;
  return new x509.X509Certificate(bytes);
}

function permutations<T>(values: T[]): T[][] {
  if (!values.length) return [[]];
  return values.flatMap((value, index) => permutations([...values.slice(0, index), ...values.slice(index + 1)]).map((rest) => [value].concat(rest)));
}

function certificateIds(certs: x509.X509Certificate[]): string[] {
  return certs.map((cert) => cert.toString("hex"));
}

describe("Marvell: certificate path regressions", () => {
  const data = Buffer.from(base64CompressedData, "base64");

  it("accepts roots and DER-duplicate instances without mutating inputs", async () => {
    const certs = [MANUFACTURER_ROOT_CERT, ...fixtureCertificates(), new x509.X509Certificate(MANUFACTURER_ROOT_CERT.rawData), OWNER_ROOT_CERT];
    certs.push(new x509.X509Certificate(certs[2].rawData));
    const original = [...certs];
    const result = await new MarvellAttestationValidator().validate(data, certs);
    expect(result.status).toBe(true);
    expect(result.chain).toHaveLength(3);
    expect(result.chain?.[0].equal(MANUFACTURER_ROOT_CERT)).toBe(true);
    expect(certs).toEqual(original);
  });

  it("backtracks from a card whose key verifies the partition but whose own signature is damaged", async () => {
    const certs = fixtureCertificates();
    const damaged = damagedSignature(certs[1]);
    await Promise.all(
      [[damaged, ...certs], [...certs].reverse().concat(damaged)].map(async (pool) => {
        const result = await new MarvellAttestationValidator().validate(data, pool);
        expect(result.status).toBe(true);
        expect(result.chain?.[1].equal(certs[1])).toBe(true);
        expect(result.chain?.some((cert) => cert.equal(damaged))).toBe(false);
      }),
    );
  });

  it("selects the same signer and DER path for every permutation of the Marvell bundle", async () => {
    const certs = fixtureCertificates();
    const expected = certificateIds([MANUFACTURER_ROOT_CERT, certs[1], certs[0]]);
    await Promise.all(
      permutations(certs).map(async (pool) => {
        const result = await new MarvellAttestationValidator().validate(data, pool);
        expect(result.status).toBe(true);
        expect(certificateIds(result.chain!)).toEqual(expected);
        expect(result.signer?.equal(certs[0])).toBe(true);
      }),
    );
  });

  it("requires a path to every configured root, rather than accepting any one root", async () => {
    const certs = fixtureCertificates();
    const validator = new MarvellAttestationValidator({ trustedCerts: [MANUFACTURER_ROOT_CERT, certs[2]] });
    // The manufacturer path remains valid, but the excluded owner partition anchor cannot be reached from the manufacturer partition.
    const result = await validator.validate(data, [certs[0], certs[1], certs[3]]);
    expect(result.status).toBe(false);
  });

  it("rejects certificate count overflow before preparing the pool", async () => {
    const result = await new MarvellAttestationValidator().validate(data, Array(65).fill(MANUFACTURER_ROOT_CERT));
    expect(result.status).toBe(false);
    if (!result.status) expect(result.error.message).toMatch(/Too many certificates/);
  });
});

describe("Marvell: generated certificate graphs", () => {
  let manufacturer: CryptoKeyPair;
  let owner: CryptoKeyPair;
  let card: CryptoKeyPair;
  let other: CryptoKeyPair;
  let signer: CryptoKeyPair;
  let wrongSigner: CryptoKeyPair;
  let roots: x509.X509Certificate[];
  let bundle: x509.X509Certificate[];
  let evidence: Uint8Array<ArrayBuffer>;
  let serial = 0;

  async function issue(subject: string, publicKeys: CryptoKeyPair, parent: string, parentKeys: CryptoKeyPair, extensions: x509.Extension[] = []): Promise<x509.X509Certificate> {
    return x509.X509CertificateGenerator.create(
      {
        serialNumber: (++serial).toString(16).padStart(4, "0"),
        subject: `CN=${subject}`,
        issuer: `CN=${parent}`,
        publicKey: publicKeys.publicKey,
        signingKey: parentKeys.privateKey,
        signingAlgorithm: { name: parentKeys.privateKey.algorithm.name, hash: "SHA-256" },
        notBefore: new Date("2024-01-01T00:00:00Z"),
        notAfter: new Date("2099-01-01T00:00:00Z"),
        extensions,
      },
      crypto,
    );
  }

  beforeAll(async () => {
    [manufacturer, owner, card, other] = await Promise.all(Array.from({ length: 4 }, () => crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])));
    [signer, wrongSigner] = await Promise.all(
      Array.from({ length: 2 }, () =>
        crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]),
      ),
    );
    roots = [await issue("Manufacturer", manufacturer, "Manufacturer", manufacturer), await issue("Owner", owner, "Owner", owner)];
    bundle = [await issue("Card", card, "Manufacturer", manufacturer), await issue("Partition", signer, "Card", card), await issue("Partition", signer, "Owner", owner)];
    evidence = new Uint8Array(zlib.gunzipSync(Buffer.from(base64CompressedData, "base64")));
    const signature = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, signer.privateKey, evidence.subarray(0, -256));
    evidence.set(new Uint8Array(signature), evidence.length - 256);
  });

  it("ignores an unrelated self-signed certificate and an invalid immediate issuer", async () => {
    const unrelated = await issue("Unrelated", other, "Unrelated", other);
    const invalidCard = await issue("Card", other, "Manufacturer", manufacturer);
    const result = await new MarvellAttestationValidator({ trustedCerts: roots }).validate(evidence, [invalidCard, unrelated, ...bundle]);
    expect(result.status).toBe(true);
    expect(certificateIds(result.chain!)).toEqual(certificateIds([roots[0], bundle[0], bundle[1]]));
  });

  it("ignores an unrelated certificate with an uninterpretable public key", async () => {
    const unrelated = await issue("Unrelated", other, "Unrelated", other);
    const asn = AsnConvert.parse(unrelated.rawData, Certificate);
    // A known RSA OID with EC key bytes parses as a certificate but fails lazy public-key decoding.
    asn.tbsCertificate.subjectPublicKeyInfo.algorithm = new AlgorithmIdentifier({ algorithm: "1.2.840.113549.1.1.1" });
    const malformed = new x509.X509Certificate(AsnConvert.serialize(asn));
    expect(() => malformed.publicKey).toThrow();
    const result = await new MarvellAttestationValidator({ trustedCerts: roots }).validate(evidence, [malformed, ...bundle]);
    expect(result.status).toBe(true);
    expect(result.signer?.equal(bundle[1])).toBe(true);
  });

  it("finds the evidence signer even when another valid partition certificate comes first", async () => {
    const wrongPartition = await issue("Other partition", wrongSigner, "Card", card);
    await Promise.all(
      [
        [wrongPartition, ...bundle],
        [...bundle, wrongPartition],
      ].map(async (pool) => {
        const result = await new MarvellAttestationValidator({ trustedCerts: roots }).validate(evidence, pool);
        expect(result.status).toBe(true);
        expect(result.signer?.equal(bundle[1])).toBe(true);
      }),
    );
  });

  it("rejects independently valid root paths whose partition public keys differ", async () => {
    const wrongPartition = await issue("Partition", wrongSigner, "Owner", owner);
    const result = await new MarvellAttestationValidator({ trustedCerts: roots }).validate(evidence, [bundle[0], bundle[1], wrongPartition]);
    expect(result.status).toBe(false);
  });

  it("rejects a missing required root even when a manufacturer path succeeds", async () => {
    const unrelatedRoot = await issue("Unrelated", other, "Unrelated", other);
    const result = await new MarvellAttestationValidator({ trustedCerts: [roots[0], unrelatedRoot] }).validate(evidence, bundle);
    expect(result.status).toBe(false);
  });

  it("supports a self-issued rollover signed by the previous key", async () => {
    const rollover = await issue("Manufacturer", card, "Manufacturer", manufacturer);
    const partition = await issue("Partition", signer, "Manufacturer", card);
    expect(rollover.subject).toBe(rollover.issuer);
    expect(await rollover.isSelfSigned(crypto)).toBe(false);
    const result = await new MarvellAttestationValidator({ trustedCerts: roots }).validate(evidence, [partition, rollover, bundle[2]]);
    expect(result.status).toBe(true);
    expect(certificateIds(result.chain!)).toEqual(certificateIds([roots[0], rollover, partition]));
  });

  it("terminates a cyclic graph and still finds an exit when one is available", async () => {
    const a = await issue("Cycle A", card, "Cycle B", other);
    const b = await issue("Cycle B", other, "Cycle A", card);
    const partition = await issue("Partition", signer, "Cycle A", card);
    const validator = new MarvellAttestationValidator({ trustedCerts: roots });
    expect((await validator.validate(evidence, [a, b, partition, bundle[2]])).status).toBe(false);
    const exit = await issue("Cycle A", card, "Manufacturer", manufacturer);
    const result = await validator.validate(evidence, [a, b, partition, exit, bundle[2]]);
    expect(result.status).toBe(true);
    expect(result.chain?.[0].equal(roots[0])).toBe(true);
    expect(result.signer?.equal(partition)).toBe(true);
  });

  it("propagates excessive path depth as a controlled resource-limit failure", async () => {
    const intermediates = await Promise.all(Array.from({ length: 15 }, (_, i) => issue(`Bridge ${i}`, card, i ? `Bridge ${i - 1}` : "Manufacturer", i ? card : manufacturer)));
    const partition = await issue("Partition", signer, "Bridge 14", card);
    const result = await new MarvellAttestationValidator({ trustedCerts: roots }).validate(evidence, [...intermediates, partition, bundle[2]]);
    expect(result.status).toBe(false);
    if (!result.status) expect(result.error).toMatchObject({ code: "LIMIT_EXCEEDED", limit: "maxDepth" });
    expect(result.signature.status).toBe("passed");
    expect(result.trust).toMatchObject({ status: "not-evaluated", reason: "resource-limit" });
  });

  it("bounds dense cyclic searches and preserves the x509 step-limit error", async () => {
    const cyclic = await Promise.all(Array.from({ length: 9 }, () => issue("Dense", card, "Dense", card)));
    const partition = await issue("Partition", signer, "Dense", card);
    const result = await new MarvellAttestationValidator({ trustedCerts: roots }).validate(evidence, [...cyclic, partition, bundle[2]]);
    expect(result.status).toBe(false);
    if (!result.status) expect(result.error).toMatchObject({ code: "LIMIT_EXCEEDED", limit: "maxSearchSteps" });
    expect(result.signature.status).toBe("passed");
    expect(result.trust).toMatchObject({ status: "not-evaluated", reason: "resource-limit" });
  });

  it.each(["maxDepth", "maxSearchSteps"] as const)("tries other signer certificates after an unrelated same-key path reaches %s", async (limit) => {
    const certs = fixtureCertificates();
    const publicKey = await certs[0].publicKey.export({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, ["verify"], crypto);
    const issuer = limit === "maxDepth" ? "Depth 0" : "Dense";
    const poison = await x509.X509CertificateGenerator.create(
      {
        serialNumber: "01",
        subject: "CN=Poison",
        issuer: `CN=${issuer}`,
        publicKey,
        signingKey: card.privateKey,
        signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
        notBefore: new Date("2024-01-01T00:00:00Z"),
        notAfter: new Date("2099-01-01T00:00:00Z"),
      },
      crypto,
    );
    // This certificate shares the evidence signing key and sorts before the genuine partition.
    expect(poison.toString("hex") < certs[0].toString("hex")).toBe(true);
    const untrusted =
      limit === "maxDepth"
        ? await Promise.all(Array.from({ length: 17 }, (_, i) => issue(`Depth ${i}`, card, `Depth ${i + 1}`, card)))
        : await Promise.all(Array.from({ length: 9 }, () => issue("Dense", card, "Dense", card)));
    const result = await new MarvellAttestationValidator().validate(Buffer.from(base64CompressedData, "base64"), [poison, ...untrusted, ...certs]);
    expect(result.status).toBe(true);
    expect(certificateIds(result.chain!)).toEqual(certificateIds([MANUFACTURER_ROOT_CERT, certs[1], certs[0]]));
  });

  it("bounds the combined certificate bytes before searching", async () => {
    const oversized = await issue("Oversized", card, "Manufacturer", manufacturer, [new x509.Extension("1.2.3.4", false, new ArrayBuffer(1024 * 1024))]);
    const result = await new MarvellAttestationValidator({ trustedCerts: roots }).validate(evidence, [oversized, ...bundle]);
    expect(result.status).toBe(false);
    if (!result.status) expect(result.error.message).toMatch(/Certificate data exceeds/);
  });

  it("bounds the total number of searches across all signer candidates and roots", async () => {
    const pairs = await Promise.all(
      Array.from({ length: 32 }, (_, i) => Promise.all([issue(`Root ${i}`, manufacturer, `Root ${i}`, manufacturer), issue("Partition", signer, `Root ${i}`, manufacturer)])),
    );
    const manyRoots = pairs.map(([root]) => root);
    const partitions = pairs.map(([, partition]) => partition);
    const result = await new MarvellAttestationValidator({ trustedCerts: manyRoots }).validate(evidence, partitions);
    expect(result.status).toBe(false);
    if (!result.status) expect(result.error.message).toMatch(/attempt limit/);
    expect(result.signature.status).toBe("passed");
    expect(result.trust).toMatchObject({ status: "not-evaluated", reason: "resource-limit" });
  });

  it("does not treat configured anchors themselves as partition signing certificates", async () => {
    const signingAnchors = [await issue("First anchor", signer, "First anchor", signer), await issue("Second anchor", signer, "Second anchor", signer)];
    const result = await new MarvellAttestationValidator({ trustedCerts: signingAnchors }).validate(evidence, signingAnchors);
    expect(result.status).toBe(false);
  });

  it("still rejects a corrupted evidence signature", async () => {
    const corrupt = evidence.slice();
    corrupt[corrupt.length - 1] ^= 1;
    const result = await new MarvellAttestationValidator({ trustedCerts: roots }).validate(corrupt, bundle);
    expect(result.status).toBe(false);
    if (!result.status) expect(result.error.message).toMatch(/attestation signature/);
  });
});
