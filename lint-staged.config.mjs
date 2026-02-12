import { existsSync } from "fs";

const IGNORED_PATTERNS = [
  "node_modules",
  "/dist/",
  "/target/",
  "/pkg/",
  "/js/wasm/",
  "/bundler-test/",
];

function filterIgnored(filenames) {
  return filenames.filter((f) => !IGNORED_PATTERNS.some((p) => f.includes(p)));
}

/** Extract package name from a file path like packages/wasm-utxo/src/foo.rs */
function getPackageName(filepath) {
  const match = filepath.match(/packages\/([^/]+)\//);
  return match?.[1];
}

/** Group files by their package name */
function groupByPackage(filenames) {
  const groups = new Map();
  for (const f of filenames) {
    const pkg = getPackageName(f);
    if (!pkg) continue;
    if (!groups.has(pkg)) groups.set(pkg, []);
    groups.get(pkg).push(f);
  }
  return groups;
}

export default {
  "*.{js,ts,tsx,mjs,cjs}": (filenames) => {
    const filtered = filterIgnored(filenames);
    if (filtered.length === 0) return [];

    const commands = [`prettier --write ${filtered.join(" ")}`];

    for (const [pkg, files] of groupByPackage(filtered)) {
      const configPath = `packages/${pkg}/eslint.config.js`;
      if (existsSync(configPath)) {
        commands.push(`npx eslint -c ${configPath} --fix ${files.join(" ")}`);
      }
    }

    return commands;
  },

  "*.{json,yaml,yml,md}": (filenames) => {
    const filtered = filterIgnored(filenames);
    if (filtered.length === 0) return [];
    return [`prettier --write ${filtered.join(" ")}`];
  },

  "*.rs": (filenames) => {
    const filtered = filterIgnored(filenames);
    if (filtered.length === 0) return [];

    const commands = [];
    for (const pkg of new Set(filtered.map(getPackageName).filter(Boolean))) {
      const manifest = `packages/${pkg}/Cargo.toml`;
      if (existsSync(manifest)) {
        commands.push(`cargo fmt --manifest-path ${manifest}`);
        // TODO: enable once pre-existing clippy warnings are fixed
        // commands.push(
        //   `cargo clippy --manifest-path ${manifest} --all-targets --all-features -- -D warnings`,
        // );
      }
    }
    return commands;
  },
};
