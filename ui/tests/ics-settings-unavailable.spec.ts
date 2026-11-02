import { expect, test } from "@playwright/test";

for (const initiallyAvailable of [false, true]) {
  test(`saved ICS settings are unknown after ${initiallyAvailable ? "a failed refresh" : "an unavailable initial read"}`, async ({ page }) => {
    let available = initiallyAvailable;
    await page.addInitScript(() => {
      localStorage.setItem("containd.auth.token", "test-token");
      localStorage.setItem("containd.auth.role", "admin");
    });
    await page.route("**/api/v1/**", async route => {
      const path = new URL(route.request().url()).pathname;
      if (path === "/api/v1/dataplane" && !available) {
        return route.fulfill({ status: 503, json: { error: "settings unavailable" } });
      }
      const json = path.startsWith("/api/v1/auth/") ? { id: "admin", role: "admin" }
        : path === "/api/v1/firewall/rules" ? []
          : path === "/api/v1/dataplane" ? { dpiEnabled: true, nfqueueGroup: 101, captureInterfaces: ["lan1"] }
            : {};
      return route.fulfill({ json, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
    });
    const loaded = page.waitForResponse("**/api/v1/dataplane");
    await page.goto("/ics/");
    await loaded;
    const settings = page.getByRole("region", { name: "Candidate DPI Settings" });
    if (initiallyAvailable) {
      await expect(settings.getByText("DPI Enabled", { exact: true })).toBeVisible();
      await expect(settings.getByText("Inline inspection configured", { exact: true })).toBeVisible();
      available = false;
      const failed = page.waitForResponse("**/api/v1/dataplane");
      await page.getByRole("button", { name: "Refresh", exact: true }).click();
      await failed;
    }
    await expect(settings.getByText("DPI status unknown", { exact: true })).toBeVisible();
    await expect(settings.getByText("Inline inspection status unknown", { exact: true })).toBeVisible();
    await expect(settings.getByText("DPI Disabled", { exact: true })).toHaveCount(0);
    await expect(settings.getByText("Inline inspection configured", { exact: true })).toHaveCount(0);
    await expect(settings.getByText("Monitor only — inline inspection is not configured", { exact: true })).toHaveCount(0);
    await expect(settings.getByText(/Inline inspection queue \(NFQUEUE\):/)).toHaveCount(0);
    await expect(settings.getByText(/Capture interfaces:/)).toHaveCount(0);
  });
}
