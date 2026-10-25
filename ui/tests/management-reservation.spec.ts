import { expect, test } from "@playwright/test";

test("Interfaces explains immutable access and exposes guard faults", async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const data: Record<string, unknown> = {
      "/api/v1/auth/me": { id: "admin", username: "containd", role: "admin" },
      "/api/v1/auth/session": { id: "admin", username: "containd", role: "admin" },
      "/api/v1/config/diff": { changed: false, changedSections: [] },
      "/api/v1/interfaces": [{ name: "lan3", device: "eth7", zone: "lan" }],
      "/api/v1/interfaces/state": [{ name: "eth7", up: true, addrs: ["10.99.99.2/24"] }],
      "/api/v1/zones": [{ name: "lan" }],
      "/api/v1/system/management-reservation": {
        active: true, device: "eth7", local: "10.99.99.2/24", sources: ["10.99.99.10", "10.99.99.3"], port: 8080,
        guard: { active: true, faults: 1, lastFault: { reason: "source address removed" } },
        rollbackFault: "rollback refused: interfaces conflicts with reserved management path",
      },
    };
    await route.fulfill({ json: data[path] ?? {} });
  });
  await page.goto("/interfaces/");
  const note = page.getByRole("complementary", { name: "Reserved management path" });
  await expect(note).toContainText("RangerDanger management access is reserved");
  await expect(note).toContainText("10.99.99.10, 10.99.99.3");
  await expect(note).toContainText("even when all interface access is disabled");
  await expect(note).toContainText("Login is still required");
  await expect(note).toContainText("source address removed");
  await expect(note).toContainText("rollback refused");
  await expect(note.getByRole("button")).toHaveCount(0);
});

test("Interfaces omits the note when no reservation is configured", async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const data = path.endsWith("/management-reservation") ? { active: false }
      : path.endsWith("/interfaces") || path.endsWith("/state") || path.endsWith("/zones") ? []
        : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json: data });
  });
  await page.goto("/interfaces/");
  await expect(page.getByRole("heading", { name: "Interfaces", exact: true })).toBeVisible();
  await expect(page.getByRole("complementary", { name: "Reserved management path" })).toHaveCount(0);
});
