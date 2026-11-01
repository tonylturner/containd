import { expect, test } from "@playwright/test";

test("Interfaces explains immutable access and exposes guard faults", async ({ page }) => {
  let bootFault = "interfaces[0].addresses conflicts with reserved management path";
  let recovery = "recovery pending: ruleset not applied";
  let listenerFaults: string[] = [];
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
        bootFault,
        recovery, listenerFaults,
        rollbackFault: "rollback refused: interfaces conflicts with reserved management path",
      },
    };
    await route.fulfill({ json: data[path] ?? {}, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  await page.goto("/interfaces/");
  const note = page.getByRole("complementary", { name: "Reserved management path" });
  await expect(note).toContainText("Management access is reserved");
  await expect(page.locator("body")).not.toContainText("RangerDanger");
  await expect(note).toContainText("10.99.99.10, 10.99.99.3");
  await expect(note).toContainText("even when all interface access is disabled");
  await expect(note).toContainText("Login is still required");
  await expect(note).toContainText("source address removed");
  await expect(note).toContainText("rollback refused");
  await expect(note.getByRole("status")).toContainText("Configuration apply paused");
  await expect(note.getByRole("status")).toContainText("Commit a safe configuration");
  await expect(note.getByRole("status")).toContainText("has not received");
  await expect(note.getByRole("status")).toContainText("recovery pending: ruleset not applied");
  await expect(note).not.toContainText("recovery: new transit dropped");
  recovery = "recovery: new transit dropped";
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(note.getByRole("status")).toContainText("recovery: new transit dropped");
  await expect(note.getByRole("button")).toHaveCount(0);
  bootFault = "";
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(note.getByRole("status")).toHaveCount(0);
  await expect(note).toContainText("Management access is reserved");
  listenerFaults = ["https 192.0.2.250:8443: cannot assign requested address"];
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(note.getByRole("status")).toContainText("Optional listener boot faults");
  await expect(note.getByRole("status")).toContainText("192.0.2.250:8443");
  await expect(note.getByRole("status")).toContainText("Reserved HTTP management remains available");
  await expect(note).not.toContainText("recovery: new transit dropped");
});

test("Interfaces omits the note when no reservation is configured", async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const data = path.endsWith("/management-reservation") ? { active: false }
      : path.endsWith("/interfaces") || path.endsWith("/state") || path.endsWith("/zones") ? []
        : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json: data, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  await page.goto("/interfaces/");
  await expect(page.getByRole("heading", { name: "Interfaces", exact: true })).toBeVisible();
  await expect(page.getByRole("complementary", { name: "Reserved management path" })).toHaveCount(0);
  await expect(page.getByRole("complementary", { name: "Boot fault" })).toHaveCount(0);
});

test("Interfaces shows a boot fault without a reservation", async ({ page }) => {
  const bootFault = "firewall.rules[3]: rule plc-write: action RESET cannot take an ics protocol";
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const data = path.endsWith("/management-reservation") ? { active: false, bootFault, recovery: "recovery: new transit dropped" }
      : path.endsWith("/interfaces") || path.endsWith("/state") || path.endsWith("/zones") ? []
        : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json: data, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  await page.goto("/interfaces/");
  await expect(page.getByRole("complementary", { name: "Reserved management path" })).toHaveCount(0);
  const fault = page.getByRole("complementary", { name: "Boot fault" }).getByRole("status");
  await expect(fault).toContainText("Configuration apply paused");
  await expect(fault).toContainText("recovery: new transit dropped");
  await expect(fault).toContainText(bootFault);
  await expect(fault).toContainText("keeps the stored management listener access");
  await expect(fault).not.toContainText("Reserved management");
  await expect(fault).toHaveClass(/text-amber/);
});
