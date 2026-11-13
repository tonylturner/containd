import { expect, test, type Page, type Route } from "@playwright/test";

const admin = { id: "admin-1", username: "containd", role: "admin", mfaEnabled: true };
const revision = { "X-Containd-Revision": "0123456789abcdef.1" };

async function openAccount(page: Page, item: "Profile" | "Change password") {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    const json = path === "/api/v1/auth/me" || path === "/api/v1/auth/session"
      ? admin
      : path === "/api/v1/zones" ? [] : {};
    return route.fulfill({ json, headers: revision });
  });
  const loaded = page.waitForResponse("**/api/v1/zones");
  await page.goto("/zones/");
  await loaded;
  await page.getByRole("button", { name: "User menu" }).click();
  await page.getByRole("button", { name: item, exact: true }).click();
  return page.getByRole("dialog", { name: "Account" });
}

test("opening Password never redirects typing after the user selects Current password", async ({ page }) => {
  const now = new Date("2026-11-13T12:00:00Z");
  await page.clock.install({ time: now });
  await page.clock.pauseAt(now);
  const dialog = await openAccount(page, "Change password");
  const current = dialog.getByLabel("Current password", { exact: true });
  const next = dialog.getByLabel("New password", { exact: true });
  await current.focus();
  // Let any deferred opening focus run between choosing a field and typing.
  // Unlike a sleep, the paused clock makes this ordering deterministic.
  await page.clock.runFor(100);
  await page.keyboard.insertText("wrong");
  await next.fill("a new long passphrase");
  await expect(current).toHaveValue("wrong");
  await expect(next).toHaveValue("a new long passphrase");

  await page.route("**/api/v1/auth/me/password", (route) =>
    route.fulfill({ status: 401, json: { error: "current password is incorrect" } }));
  const submitted = page.waitForResponse("**/api/v1/auth/me/password");
  await dialog.getByRole("button", { name: "Update password" }).click();
  const response = await submitted;
  expect(response.request().postDataJSON()).toEqual({
    currentPassword: "wrong",
    newPassword: "a new long passphrase",
  });
  await expect(dialog.getByText("current password is incorrect", { exact: true })).toBeVisible();
});

test("a delayed session check preserves password fields and focus", async ({ page }) => {
  const dialog = await openAccount(page, "Change password");
  let receive!: (route: Route) => void;
  const checking = new Promise<Route>((resolve) => { receive = resolve; });
  await page.route("**/api/v1/auth/me", (route) => { receive(route); });
  await page.evaluate(() => window.dispatchEvent(new Event("containd:auth:expired")));
  const check = await checking;
  const current = dialog.getByLabel("Current password", { exact: true });
  const next = dialog.getByLabel("New password", { exact: true });
  await current.fill("current passphrase");
  await next.fill("a new long passphrase");
  const checked = page.waitForResponse("**/api/v1/auth/me");
  await check.fulfill({ json: { ...admin, firstName: "Updated" }, headers: revision });
  await (await checked).finished();
  await expect(current).toHaveValue("current passphrase");
  await expect(next).toHaveValue("a new long passphrase");
  await expect(next).toBeFocused();
  await expect(page).toHaveURL(/\/zones\/$/);
});

test("a delayed profile save updates me without resetting password drafts", async ({ page }) => {
  const dialog = await openAccount(page, "Profile");
  let receive!: (route: Route) => void;
  const saving = new Promise<Route>((resolve) => { receive = resolve; });
  await page.route("**/api/v1/auth/me", (route) => { receive(route); });
  await dialog.getByLabel("First name", { exact: true }).fill("Updated");
  await dialog.getByRole("button", { name: "Save profile" }).click();
  const save = await saving;
  expect(save.request().method()).toBe("PATCH");
  expect(save.request().postDataJSON()).toMatchObject({ firstName: "Updated" });
  await dialog.getByRole("button", { name: "Password", exact: true }).click();
  const current = dialog.getByLabel("Current password", { exact: true });
  const next = dialog.getByLabel("New password", { exact: true });
  await current.fill("current passphrase");
  await next.fill("a new long passphrase");
  await save.fulfill({ json: { ...admin, firstName: "Updated" }, headers: revision });
  // Saving finishes only after onSaved has replaced Shell's me object.
  await expect(dialog.getByRole("button", { name: "Update password" })).toBeEnabled();
  await expect(current).toHaveValue("current passphrase");
  await expect(next).toHaveValue("a new long passphrase");
  await expect(next).toBeFocused();
});
