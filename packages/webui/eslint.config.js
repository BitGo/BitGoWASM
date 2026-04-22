import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "dist/",
      "node_modules/",
      "wasm/",
      "webpack.config.js",
      "playwright.config.ts",
      "scripts/",
      "tests/",
    ],
  },
  tseslint.configs.recommended,
  {
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: {
      parserOptions: {
        project: ["./tsconfig.json"],
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
);
