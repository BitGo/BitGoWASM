#!/usr/bin/env node
import { execSync } from "child_process";
import { appendFileSync } from "fs";

// Per-package matrix entries. Each object becomes one `matrix.include`
// combination in the `test` job. The flags gate steps there:
//   - needs-wasm-pack:      download the build artifact (wasm .js/.wasm)
//   - has-wasm-pack-tests:  run `npm run test:wasm-pack-{node,chrome}`
// Keeping the flags here (instead of a static `include:` block in the
// workflow) is what actually lets `detect-changes` shrink the matrix — a
// workflow `include:` entry whose `package` conflicts with the base matrix
// spawns a NEW job rather than being filtered out, which previously
// re-added every package on every PR.
const PACKAGE_CONFIG = [
  { package: "wasm-utxo", "needs-wasm-pack": true, "has-wasm-pack-tests": true },
  { package: "wasm-bip32", "needs-wasm-pack": false, "has-wasm-pack-tests": false },
  { package: "wasm-mps", "needs-wasm-pack": false, "has-wasm-pack-tests": false },
  { package: "wasm-solana", "needs-wasm-pack": false, "has-wasm-pack-tests": false },
  { package: "wasm-dot", "needs-wasm-pack": false, "has-wasm-pack-tests": false },
  { package: "wasm-ton", "needs-wasm-pack": false, "has-wasm-pack-tests": false },
  { package: "wasm-privacy-coin", "needs-wasm-pack": false, "has-wasm-pack-tests": false },
];

const ALL_PACKAGES = PACKAGE_CONFIG.map((p) => p.package);

function setOutput(entries) {
  const value = JSON.stringify(entries);
  appendFileSync(process.env.GITHUB_OUTPUT, `packages=${value}\n`);
  console.log(`Packages to test: ${value}`);
}

function entriesFor(pkgs) {
  const wanted = new Set(pkgs);
  return PACKAGE_CONFIG.filter((p) => wanted.has(p.package));
}

// Non-PR events (push to master, workflow_dispatch): run everything
if (process.env.GITHUB_EVENT_NAME !== "pull_request") {
  setOutput(PACKAGE_CONFIG);
  process.exit(0);
}

const base = process.env.BASE_SHA;
const head = process.env.HEAD_SHA;

const changedFiles = execSync(`git diff --name-only ${base} ${head}`)
  .toString()
  .trim()
  .split("\n")
  .filter(Boolean);

// Shared infrastructure changes → run all packages
const sharedChanged = changedFiles.some((f) =>
  /^(\.github\/|package\.json$|lerna\.json$|package-lock\.json$)/.test(f),
);
if (sharedChanged) {
  setOutput(PACKAGE_CONFIG);
  process.exit(0);
}

// Per-package detection; fall back to all if nothing package-specific changed
const changed = ALL_PACKAGES.filter((pkg) =>
  changedFiles.some((f) => f.startsWith(`packages/${pkg}/`)),
);
setOutput(changed.length > 0 ? entriesFor(changed) : PACKAGE_CONFIG);
