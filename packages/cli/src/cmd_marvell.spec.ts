import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import * as x509 from "@peculiar/x509";
import { base64CompressedData, certChain } from "../../marvell/test/fixtures";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const cli = fileURLToPath(new URL("./main.ts", import.meta.url));
let directory: string;

beforeAll(() => {
  directory = mkdtempSync(join(tmpdir(), "attestation-marvell-cli-"));
  const evidence = Buffer.from(base64CompressedData, "base64");
  writeFileSync(join(directory, "evidence.bin"), evidence);
  writeFileSync(join(directory, "certificates.pem"), certChain);
  const certs = x509.PemConverter.decode(certChain).map((cert) => new x509.X509Certificate(cert));
  writeFileSync(
    join(directory, "missing-owner-card.pem"),
    certs
      .filter((_, i) => i !== 3)
      .map((cert) => cert.toString("pem"))
      .join("\n"),
  );
  writeFileSync(
    join(directory, "missing-owner-partition.pem"),
    certs
      .filter((_, i) => i !== 2)
      .map((cert) => cert.toString("pem"))
      .join("\n"),
  );
  const corrupt = gunzipSync(evidence);
  corrupt[corrupt.length - 1] ^= 1;
  writeFileSync(join(directory, "corrupt.bin"), corrupt);
});

afterAll(() => rmSync(directory, { recursive: true, force: true }));

function verify(file: string, bundle = "certificates.pem") {
  return spawnSync(process.execPath, ["--import", "tsx", cli, "marvell", "verify", join(directory, file), "--cert", join(directory, bundle)], {
    cwd: root,
    env: { ...process.env, TSX_TSCONFIG_PATH: join(root, "tsconfig.json") },
    encoding: "utf8",
    timeout: 10000,
  });
}

describe("Marvell CLI verification", () => {
  it("uses the certificate bundle as untrusted intermediates and keeps bundled roots", () => {
    const result = verify("evidence.bin");
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toMatch(/Status: PASSED/);
  });

  it("still rejects a corrupted evidence signature", () => {
    const result = verify("corrupt.bin");
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/Status: FAILED/);
    expect(result.stderr).toMatch(/Failed to verify the attestation signature/);
  });

  it.each(["missing-owner-card.pem", "missing-owner-partition.pem"])("enforces the Google profile for %s", (bundle) => {
    const result = verify("evidence.bin", bundle);
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/Google Cloud HSM card\/partition certificate relationships/);
  });
});
