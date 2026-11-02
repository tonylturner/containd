import { expect, test } from "@playwright/test";
import { mkdir } from "node:fs/promises";

test.use({ timezoneId: "UTC" });
const shots = process.env.CAS_SCREENSHOTS_DIR ?? "test-results/cas";

test("server-owned commit-confirmed reminder follows navigation and clears only when the snapshot clears it", async ({ page }) => {
  const deadline = new Date(Date.now() + 120_000).toISOString();
  const state: { pendingConfirm: { deadline: string } | null; changed: boolean } = { pendingConfirm: { deadline }, changed: false };
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async route => {
    const path = new URL(route.request().url()).pathname.replace("/api/v1", "");
    const json = path.startsWith("/auth/") ? { id: "admin", role: "admin" }
      : path === "/config/diff" ? { changed: state.changed, changedSections: [], pendingConfirm: state.pendingConfirm, running: {}, candidate: {} }
      : ["/config/backups", "/zones"].includes(path) ? [] : {};
    return route.fulfill({ json, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  const reminder = page.getByRole("link", { name: /^Commit-confirmed pending: confirm before/ });
  await page.goto("/config/");
  await expect(reminder).toHaveText(`Commit-confirmed pending: confirm before ${deadline.slice(11, 19)}`);
  await expect(reminder).toHaveAttribute("href", "/config/?tab=diff");
  await expect(page.getByText("Confirm before this deadline to keep these changes; otherwise they will be undone automatically.", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Review diff", exact: true })).toHaveCount(0);
  await expect(page.getByText("Saved changes are not active yet.", { exact: true })).toHaveCount(0);
  await page.goto("/zones/");
  await expect(reminder).toBeVisible();
  await mkdir(shots, { recursive: true });
  for (const width of [1280, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await page.screenshot({ path: `${shots}/pending-reminder-${width}.png`, fullPage: true, animations: "disabled" });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  }
  await reminder.click();
  await expect(page).toHaveURL(/\/config\/\?tab=diff/);
  await expect(reminder).toBeVisible();
  // Candidate dirtiness and the confirmation timer are independent server state.
  state.changed = true;
  let refreshed = page.waitForResponse("**/api/v1/config/diff");
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:staged")));
  await (await refreshed).finished();
  await expect(page.getByText("Saved changes are not active yet.", { exact: true })).toBeVisible();
  await expect(reminder).toBeVisible();
  state.pendingConfirm = null;
  refreshed = page.waitForResponse("**/api/v1/config/diff");
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:committed")));
  await (await refreshed).finished();
  await expect(reminder).toHaveCount(0);
  await expect(page.getByText("Saved changes are not active yet.", { exact: true })).toBeVisible();
});
