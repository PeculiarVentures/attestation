import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import assert from "node:assert/strict";
import "@abraham/reflection";

const require = createRequire(import.meta.url);
for (const name of ["common", "marvell", "yubico"]) {
  const pkg = `@peculiar/attestation-${name}`;
  await import(pkg);
  require(pkg);
  const packed = JSON.parse(execFileSync("npm", ["pack", "--dry-run", "--json", "--workspace", pkg], { encoding: "utf8" }));
  const files = new Set((Array.isArray(packed) ? packed[0] : packed[pkg]).files.map((file) => file.path));
  assert(files.has("build/index.js"), `${pkg} is missing its entry point`);
  assert(files.has("build/index.d.ts"), `${pkg} is missing its declarations`);
}
const cli = JSON.parse(execFileSync("npm", ["pack", "--dry-run", "--json", "--workspace", "@peculiar/attestation-cli"], { encoding: "utf8" }));
assert(
  (Array.isArray(cli) ? cli[0] : cli["@peculiar/attestation-cli"]).files.some((file) => file.path === "bin/main.js"),
  "CLI entry point is missing",
);
const help = execFileSync(process.execPath, ["packages/cli/bin/main.js", "--help"], { encoding: "utf8" });
assert.match(help, /Usage: attest/);
console.log("Package entries and CLI smoke checks passed.");
