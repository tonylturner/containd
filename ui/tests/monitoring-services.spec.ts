import { expect, test } from "@playwright/test";

// The monitoring overview renders the services status through its typed shape.

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };

function meter(sparkline: number[] = []) {
  return {
    sparkline,
    count: sparkline.reduce((a, b) => a + b, 0),
    rate_per_min: 0,
    errors_sparkline: [],
    errors_count: 0,
    errors_rate_per_min: 0,
  };
}

test("monitoring overview reads the typed services status", async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const p = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (p === "/api/v1/auth/me" || p === "/api/v1/auth/session") body = user;
    if (p === "/api/v1/events" || p === "/api/v1/flows") body = [];
    if (p === "/api/v1/services/status") {
      body = {
        dns: { enabled: true, running: true, ...meter() },
        ntp: { enabled: true, running: false, ...meter() },
        envoy: { note: "", ...meter([4]), rate_per_min: 2.5, errors_rate_per_min: 0.5 },
        av: { available: false, error: "engine unavailable" },
      };
    }
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/services/status");
  await page.goto("/monitoring/");
  await loaded;
  const health = page.getByRole("region", { name: "Services Health" });
  await expect(health).toContainText("2.5 /min");
  await expect(health).toContainText("0.5 err/min");
  const tile = (label: string) => health.locator("div.rounded-lg").filter({ hasText: label });
  await expect(tile("DNS")).toContainText("running");
  await expect(tile("NTP")).toContainText("stopped");
  await expect(tile("DHCP")).toContainText("off");
});
