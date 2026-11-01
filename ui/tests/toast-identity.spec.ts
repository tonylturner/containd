import { expect, test } from "@playwright/test";

test("simultaneous notifications have unique keys even when the clock is fixed", async ({ page }) => {
  const errors: string[] = [];
  page.on("console", (message) => { if (message.type() === "error") errors.push(message.text()); });
  await page.clock.setFixedTime(new Date("2026-10-30T12:00:00Z"));
  await page.route("**/api/v1/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    const json = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin", username: "containd", role: "admin" }
      : path.endsWith("/config/diff") ? { changed: false }
      : path.endsWith("/dhcp/leases") ? { leases: [] } : {};
    return route.fulfill({ json, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  await page.goto("/dhcp/");
  const notifications = page.getByRole("status", { name: "Notifications" });
  await expect(notifications.getByRole("alert").filter({ hasText: "Leases updated" }).first()).toBeVisible();
  await expect(notifications.getByRole("alert").filter({ hasText: "DHCP status refreshed" }).first()).toBeVisible();
  expect(errors).toEqual([]);
});
