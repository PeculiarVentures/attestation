import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { isPublished, publishRelease, releasePlan } from "./release.mjs";

function fixture(t, manifests) {
  const root = mkdtempSync(join(tmpdir(), "attestation-release-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  writeFileSync(join(root, "package.json"), JSON.stringify({ version: "3.0.0" }));
  mkdirSync(join(root, "packages"));
  for (const [dir, pkg] of Object.entries(manifests)) {
    mkdirSync(join(root, "packages", dir));
    writeFileSync(join(root, "packages", dir, "package.json"), JSON.stringify({ version: "3.0.0", ...pkg }));
  }
  return root;
}

const manifests = {
  cli: { name: "cli", dependencies: { yubico: "^3.0.0", marvell: "^3.0.0" } },
  common: { name: "common" },
  marvell: { name: "marvell", dependencies: { common: "^3.0.0" } },
  yubico: { name: "yubico", dependencies: { common: "^3.0.0" } },
};

test("publishes dependencies before dependents", (t) => {
  const { packages } = releasePlan(fixture(t, manifests));
  const index = (name) => packages.findIndex((pkg) => pkg.name === name);
  assert(index("common") < index("yubico"));
  assert(index("common") < index("marvell"));
  assert(index("yubico") < index("cli"));
  assert(index("marvell") < index("cli"));
});

test("rejects inconsistent versions and stale workspace ranges", (t) => {
  assert.throws(() => releasePlan(fixture(t, { common: { name: "common", version: "2.0.0" } })), /expected 3.0.0/);
  assert.throws(
    () =>
      releasePlan(
        fixture(t, {
          common: { name: "common" },
          cli: { name: "cli", dependencies: { common: "^2.0.0" } },
        }),
      ),
    /expected \^3.0.0/,
  );
});

test("rejects dependency cycles", (t) => {
  assert.throws(
    () =>
      releasePlan(
        fixture(t, {
          a: { name: "a", dependencies: { b: "^3.0.0" } },
          b: { name: "b", dependencies: { a: "^3.0.0" } },
        }),
      ),
    /dependency cycle/,
  );
});

test("only E404 means a release version is absent", () => {
  const pkg = { name: "common", version: "3.0.0" };
  assert.equal(
    isPublished(pkg, ".", () => ({ status: 0, stdout: '"3.0.0"' })),
    true,
  );
  assert.equal(
    isPublished(pkg, ".", () => ({ status: 1, stdout: '{"error":{"code":"E404"}}' })),
    false,
  );
  assert.throws(() => isPublished(pkg, ".", () => ({ status: 1, stdout: '{"error":{"code":"E401"}}' })), /Cannot check/);
  assert.throws(() => isPublished(pkg, ".", () => ({ status: 1, stdout: "", stderr: "Network error" })), /Network error/);
});

test("retry skips existing packages and stops after a failed publication", (t) => {
  const root = fixture(t, manifests);
  const plan = releasePlan(root);
  const calls = [];
  const npm = (args) => {
    calls.push(args);
    if (args[0] === "view") {
      return args[1].startsWith("common@") ? { status: 0, stdout: '"3.0.0"' } : { status: 1, stdout: '{"error":{"code":"E404"}}' };
    }
    return { status: 1 };
  };
  assert.throws(() => publishRelease(plan, root, npm), /Publication failed/);
  const publishCalls = calls.filter(([command]) => command === "publish");
  assert.equal(publishCalls.length, 1);
  assert.notEqual(publishCalls[0][2], "packages/common");
  assert(publishCalls[0].includes("--ignore-scripts"));
  assert(publishCalls[0].includes("--provenance"));
});

test("rejects publishing an older missing version over npm latest", (t) => {
  const root = fixture(t, { common: { name: "common" } });
  const calls = [];
  const npm = (args) => {
    calls.push(args);
    return args[2] === "dist-tags.latest" ? { status: 0, stdout: '["4.0.0"]' } : { status: 1, stdout: '{"error":{"code":"E404"}}' };
  };
  assert.throws(() => publishRelease(releasePlan(root), root, npm), /Refusing to replace/);
  assert(!calls.some(([command]) => command === "publish"));
});
