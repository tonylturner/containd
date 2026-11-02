import { expect, test } from "@playwright/test";
import { observation, protectionAPI } from "./fixtures/protection-api";

test("creating a user returns to that account and offers confirmed MFA immediately on mobile", async ({ page }) => {
  await protectionAPI(page, observation());
  const users = [{ id: "admin", username: "containd", role: "admin" }];
  const writes: { path: string; body: any }[] = [];
  await page.route("**/api/v1/users", async route => {
    if (route.request().method() === "GET") return route.fulfill({ json: users });
    const { password: _password, ...user } = route.request().postDataJSON();
    writes.push({ path: "create", body: user });
    users.push({ ...user, id: "new-user" });
    return route.fulfill({ json: users.at(-1) });
  });
  await page.route("**/api/v1/users/new-user/mfa/require", async route => {
    writes.push({ path: "require", body: route.request().postDataJSON() });
    return route.fulfill({ json: { status: "required" } });
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/system/users/");
  await page.getByRole("button", { name: "Add User", exact: true }).click();
  await page.getByPlaceholder("username", { exact: true }).fill("operator-new");
  await page.getByPlaceholder("password", { exact: true }).fill("strong-test-password");
  await page.getByRole("button", { name: "Create user", exact: true }).click();
  await expect(page.getByPlaceholder("Search users (name, email, role)")).toHaveValue("operator-new");
  await expect(page.getByRole("heading", { name: "Add User", exact: true })).toHaveCount(0);
  const requireMFA = page.getByRole("button", { name: "Require MFA", exact: true });
  await expect(requireMFA).toBeVisible();
  await requireMFA.click();
  await expect(page.getByRole("dialog")).toContainText("operator-new");
  expect(writes.map(w => w.path)).toEqual(["create"]);
  await page.getByRole("dialog").getByRole("button", { name: "Require MFA", exact: true }).click();
  await expect.poll(() => writes.length).toBe(2);
  expect(writes[1]).toEqual({ path: "require", body: {} });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
