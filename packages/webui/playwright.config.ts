import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  use: {
    baseURL: "http://localhost:9090",
    headless: true,
  },
  webServer: {
    command: "npx webpack serve --mode development --port 9090",
    port: 9090,
    timeout: 60_000,
    reuseExistingServer: true,
  },
  projects: [
    {
      name: "chromium",
      use: { browserName: "chromium" },
    },
  ],
});
