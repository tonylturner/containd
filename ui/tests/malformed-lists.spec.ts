import { expect, test } from "@playwright/test";

import { routes } from "./fixtures/routes";

// Every page must survive a server answering 200 with the wrong shape: a list
// endpoint returning an object, string or null. A malformed body reads as
// unavailable, never as a crash or as a verified-empty list.

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };

for (const [name, body] of [["object", { unexpected: true }], ["string", "unexpected"], ["null", null]] as const) {
  for (const path of routes) {
    test(`${path} survives ${name} bodies`, async ({ page }) => {
      const pageErrors: string[] = [];
      page.on("pageerror", (err) => pageErrors.push(String(err)));
      await page.addInitScript(() => {
        localStorage.setItem("containd.auth.token", "test-token");
        localStorage.setItem("containd.auth.role", "admin");
      });
      await page.route("**/api/v1/**", async (route) => {
        const p = new URL(route.request().url()).pathname;
        if (p === "/api/v1/auth/me" || p === "/api/v1/auth/session") {
          await route.fulfill({ json: user });
          return;
        }
        await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
      });
      await page.goto(path);
      await page.waitForLoadState("networkidle");
      expect(pageErrors).toEqual([]);
      await expect(page.getByText("Application error")).toHaveCount(0);
    });
  }
}

for (const [path, endpoint, message] of [
  ["/alerts", "/api/v1/events", "Failed to load alerts."],
  ["/flows", "/api/v1/flows", "Flows unavailable"],
  ["/templates", "/api/v1/templates/ics", "ICS templates unavailable"],
  ["/sessions", "/api/v1/conntrack", "malformed connection list"],
] as const) {
  test(`${path} reports a non-list ${endpoint} body as unavailable`, async ({ page }) => {
    const pageErrors: string[] = [];
    page.on("pageerror", (err) => pageErrors.push(String(err)));
    await page.addInitScript(() => {
      localStorage.setItem("containd.auth.token", "test-token");
      localStorage.setItem("containd.auth.role", "admin");
    });
    await page.route("**/api/v1/**", async (route) => {
      const p = new URL(route.request().url()).pathname;
      const body = p === "/api/v1/auth/me" || p === "/api/v1/auth/session" ? user
        : p === endpoint ? { items: [{ id: 1 }] }
          : p.endsWith("/config/diff") ? { changed: false, changedSections: [] } : [];
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
    });
    await page.goto(path);
    await expect(page.getByText(message, { exact: false }).first()).toBeVisible();
    expect(pageErrors).toEqual([]);
  });
}
