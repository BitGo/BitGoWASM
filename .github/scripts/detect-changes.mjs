#!/usr/bin/env node
import { execSync } from 'child_process';
import { appendFileSync } from 'fs';

const ALL_PACKAGES = ['wasm-bip32', 'wasm-mps', 'wasm-utxo', 'wasm-solana', 'wasm-dot', 'wasm-ton'];

function setOutput(packages) {
  const value = JSON.stringify(packages);
  appendFileSync(process.env.GITHUB_OUTPUT, `packages=${value}\n`);
  console.log(`Packages to test: ${value}`);
}

// Non-PR events (push to master, workflow_dispatch): run everything
if (process.env.GITHUB_EVENT_NAME !== 'pull_request') {
  setOutput(ALL_PACKAGES);
  process.exit(0);
}

const base = process.env.BASE_SHA;
const head = process.env.HEAD_SHA;

const changedFiles = execSync(`git diff --name-only ${base} ${head}`)
  .toString().trim().split('\n').filter(Boolean);

// Shared infrastructure changes → run all packages
const sharedChanged = changedFiles.some(f =>
  /^(\.github\/|package\.json$|lerna\.json$|package-lock\.json$)/.test(f)
);
if (sharedChanged) {
  setOutput(ALL_PACKAGES);
  process.exit(0);
}

// Per-package detection; fall back to all if nothing package-specific changed
const changed = ALL_PACKAGES.filter(pkg =>
  changedFiles.some(f => f.startsWith(`packages/${pkg}/`))
);
setOutput(changed.length > 0 ? changed : ALL_PACKAGES);
