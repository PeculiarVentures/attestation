import { defineConfig } from "tsdown";

export default defineConfig([
  {
    workspace: { include: ["packages/common", "packages/marvell", "packages/yubico"] },
    entry: { index: "src/index.ts" },
    format: ["esm"],
    platform: "neutral",
    // TypeScript 7 has no compiler API for tsc declarations, so Oxc generates them (isolatedDeclarations rules apply).
    dts: { generator: "oxc" },
    clean: true,
    unbundle: true,
    fixedExtension: false,
    deps: { neverBundle: true },
    exports: { legacy: true },
    inputOptions: { experimental: { attachDebugInfo: "none" } },
    outputOptions: {
      comments: { legal: true, annotation: true, jsdoc: false },
    },
    outDir: "build",
    tsconfig: "../../tsconfig.json",
    attw: { level: "error", profile: "esm-only" },
  },
  {
    workspace: { include: ["packages/cli"] },
    entry: { main: "src/main.ts" },
    format: ["esm"],
    platform: "node",
    dts: false,
    clean: true,
    fixedExtension: false,
    deps: { neverBundle: true },
    inputOptions: { experimental: { attachDebugInfo: "none" } },
    outputOptions: {
      comments: { legal: true, annotation: true, jsdoc: false },
    },
    outDir: "bin",
    tsconfig: "../../tsconfig.json",
  },
]);
