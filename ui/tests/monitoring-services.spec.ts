import { seriesResponse } from "./fixtures/telemetry";
import { expect, test } from "@playwright/test";

// The monitoring overview renders the services status through its typed shape.

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };

function meter(sparkline: number[] = []) {
  return {
    count: sparkline.reduce((a, b) => a + b, 0),
    errors_count: 0,
  };
}

test("monitoring overview reads the typed services status", async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const p = url.pathname;
    if (p === "/api/v1/telemetry/series") {
      const body = seriesResponse(url, [1]);
      // 5 events / 120 seconds = 2.5 per minute (partial interval).
      body.series[0].points.at(-1)!.q = "partial";
      body.series[0].points.at(-1)!.v = url.searchParams.get("metric") === "service.errors" ? "1" : "5";
      body.series[0].points.at(-1)!.d = 120;
      return route.fulfill({ json: body });
    }
    let body: unknown = {};
    if (p === "/api/v1/auth/me" || p === "/api/v1/auth/session") body = user;
    if (p === "/api/v1/events" || p === "/api/v1/flows") body = [];
    if (p === "/api/v1/services/status") {
      body = {
        faults: [],
        dns: { enabled: true, running: true, ...meter() },
        ntp: { enabled: true, running: false, ...meter() },
        vpn: { wireguard_enabled: false },
        envoy: { note: "", ...meter([4]) },
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
  await expect(health).toContainText("errors 0.5 /min");
  const tile = (label: string) => health.locator("div.rounded-lg").filter({ hasText: label });
  await expect(tile("DNS")).toContainText("running");
  await expect(tile("NTP")).toContainText("stopped");
  await expect(tile("DHCP")).toContainText("Unknown");
  await expect(tile("VPN")).toContainText("Unknown");
});
