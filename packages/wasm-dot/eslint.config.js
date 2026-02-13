import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        project: ["./tsconfig.json", "./tsconfig.test.json"],
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    ignores: [
      "dist/",
      "pkg/",
      "target/",
      "node_modules/",
      "js/wasm/",
      "bundler-test/",
      "cli/",
      "bips/",
      "*.config.js",
    ],
  },
  // Ban Node.js globals in production code
  {
    files: ["js/**/*.ts"],
    rules: {
      "no-restricted-globals": [
        "error",
        {
          name: "Buffer",
          message: "Use Uint8Array instead of Buffer for ESM compatibility.",
        },
        {
          name: "process",
          message: "Avoid Node.js process global for ESM compatibility.",
        },
        {
          name: "__dirname",
          message: "Use import.meta.url instead of __dirname for ESM.",
        },
        {
          name: "__filename",
          message: "Use import.meta.url instead of __filename for ESM.",
        },
      ],
    },
  },
);
