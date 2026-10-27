import { defineConfig } from "tsdown";

export default defineConfig([
  {
    workspace: { include: ["packages/common", "packages/marvell", "packages/yubico"] },
    entry: { index: "src/index.ts" },
    format: ["esm"],
    platform: "neutral",
    dts: true,
    clean: true,
    unbundle: true,
    fixedExtension: false,
    deps: { neverBundle: true },
    outDir: "build",
    tsconfig: "../../tsconfig.json",
    attw: { level: "error", profile: "esm-only" },
  },
  {
    workspace: { include: ["packages/cli"] },
    entry: { main: "src/main.ts" },
    format: ["esm"],
    platform: "node",
    clean: true,
    fixedExtension: false,
    deps: { neverBundle: true },
    outDir: "bin",
    tsconfig: "../../tsconfig.json",
  },
]);
