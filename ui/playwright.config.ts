import { defineConfig } from "@playwright/test";

// Override with PLAYWRIGHT_PORT when 3100 is taken by another local server;
// otherwise reuseExistingServer would silently test whatever answers there.
const port = Number(process.env.PLAYWRIGHT_PORT ?? 3100);

export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    headless: true,
  },
  webServer: {
    command: `npm run dev -- --hostname 127.0.0.1 --port ${port}`,
    port,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
