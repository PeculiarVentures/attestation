import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const stableVersion = /^\d+\.\d+\.\d+$/;

export function releasePlan(root) {
  const { version } = readJson(resolve(root, "package.json"));
  if (!stableVersion.test(version)) throw new Error("The root package must have a stable release version");
  const packages = new Map();
  for (const dir of readdirSync(resolve(root, "packages"), { withFileTypes: true })) {
    if (!dir.isDirectory()) continue;
    const path = `packages/${dir.name}`;
    const manifest = readJson(resolve(root, path, "package.json"));
    if (manifest.private) continue;
    if (manifest.version !== version) {
      throw new Error(`${manifest.name} is ${manifest.version}; expected ${version}`);
    }
    packages.set(manifest.name, { path, ...manifest });
  }
  if (!packages.size) throw new Error("No public workspace packages found");

  const ordered = [];
  const visited = new Set();
  const visiting = new Set();
  const visit = (name) => {
    if (visited.has(name)) return;
    if (visiting.has(name)) throw new Error(`Workspace dependency cycle at ${name}`);
    visiting.add(name);
    const pkg = packages.get(name);
    for (const [dep, range] of Object.entries({ ...pkg.dependencies, ...pkg.peerDependencies })) {
      if (!packages.has(dep)) continue;
      if (range !== `^${version}` && range !== version) {
        throw new Error(`${pkg.name} depends on ${dep}@${range}; expected ^${version} or ${version}`);
      }
      visit(dep);
    }
    visiting.delete(name);
    visited.add(name);
    ordered.push(pkg);
  };
  [...packages.keys()].sort().forEach(visit);
  return { version, packages: ordered };
}

function runNpm(args, root) {
  return spawnSync("npm", args, { cwd: root, encoding: "utf8" });
}

function registryValue(args, root, npm) {
  const result = npm(["view", ...args, "--json"], root);
  if (result.error) throw result.error;
  if (result.status === 0) {
    const value = JSON.parse(result.stdout);
    return Array.isArray(value) && value.length === 1 ? value[0] : value;
  }
  let code;
  try {
    code = JSON.parse(result.stdout).error?.code;
  } catch {
    // A network or authentication error is not evidence that a version is missing.
  }
  if (code === "E404") return undefined;
  throw new Error(`Cannot check ${args[0]}: ${result.stderr || result.stdout}`);
}

export function isPublished(pkg, root, npm = runNpm) {
  const version = registryValue([`${pkg.name}@${pkg.version}`, "version"], root, npm);
  if (version === undefined) return false;
  if (version !== pkg.version) throw new Error(`Unexpected registry response for ${pkg.name}@${pkg.version}`);
  return true;
}

function assertLatestWillNotMoveBackwards(pkg, root, npm) {
  const latest = registryValue([pkg.name, "dist-tags.latest"], root, npm);
  if (latest === undefined) return;
  if (typeof latest !== "string" || !stableVersion.test(latest)) {
    throw new Error(`Cannot safely compare ${pkg.name} latest version: ${JSON.stringify(latest)}`);
  }
  const currentParts = pkg.version.split(".").map(Number);
  const latestParts = latest.split(".").map(Number);
  for (let index = 0; index < currentParts.length; index++) {
    if (currentParts[index] > latestParts[index]) return;
    if (currentParts[index] < latestParts[index]) {
      throw new Error(`Refusing to replace ${pkg.name} latest ${latest} with older ${pkg.version}; use a maintenance dist-tag`);
    }
  }
}

export function publishRelease(plan, root, npm = runNpm) {
  for (const pkg of plan.packages) {
    if (isPublished(pkg, root, npm)) {
      console.log(`${pkg.name}@${pkg.version} is already published; skipping`);
      continue;
    }
    assertLatestWillNotMoveBackwards(pkg, root, npm);
    const result = npm(["publish", "--workspace", pkg.path, "--ignore-scripts", "--access", "public", "--provenance"], root);
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    if (result.error) throw result.error;
    if (result.status !== 0) throw new Error(`Publication failed for ${pkg.name}@${pkg.version}`);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
  const plan = releasePlan(root);
  const command = process.argv[2];
  if (command === "verify") {
    if (process.env.GITHUB_EVENT_NAME === "workflow_dispatch" && process.env.GITHUB_REF_NAME !== `v${plan.version}`) {
      throw new Error(`Tag ${process.env.GITHUB_REF_NAME} does not match v${plan.version}`);
    }
    console.log(`Release v${plan.version}: ${plan.packages.map((pkg) => pkg.name).join(", ")}`);
  } else if (command === "publish") {
    publishRelease(plan, root);
  } else {
    throw new Error("Usage: node scripts/release.mjs <verify|publish>");
  }
}
