import { expect, test } from "@playwright/test";

// Until the first event list answers, the alerts page shows it is loading
// rather than an empty state that reads as a confirmed-empty list.

test("alerts show loading, not the empty state, until the first list answers", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (err) => pageErrors.push(String(err)));
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => { release = resolve; });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/events") {
      await held;
      await route.fulfill({ json: [], headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
      return;
    }
    const json = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin", username: "containd", role: "admin" }
      : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });

  const requested = page.waitForRequest((r) => new URL(r.url()).pathname === "/api/v1/events");
  await page.goto("/alerts/");
  await requested;
  await expect(page.locator("main .animate-pulse").first()).toBeVisible();
  await expect(page.getByText("No IDS alerts", { exact: true })).toHaveCount(0);
  await expect(page.getByPlaceholder("Search alerts by message, ID, anomaly type, IP...")).toHaveCount(0);

  const answered = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/events");
  release();
  await answered;
  await expect(page.getByText("No IDS alerts", { exact: true })).toBeVisible();
  await expect(page.getByText("No alerts yet.", { exact: false })).toBeVisible();
  await expect(page.locator("main .animate-pulse")).toHaveCount(0);
  expect(pageErrors).toEqual([]);
});
