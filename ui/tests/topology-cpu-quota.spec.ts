import { expect, test } from "./fixtures/topology-test";

for (const quota of ["50000 100000", "max", ""]) {
  test(`Physical CPU quota is a setting, not measured utilization (${quota || "unknown"})`, async ({ page }) => {
    await page.route("**/api/v1/**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      const json = path.includes("/auth/") ? { id: "admin", username: "containd", role: "admin" }
        : path === "/api/v1/config/running" ? { interfaces: [] }
        : path === "/api/v1/system/inspection" ? {
          host: {}, runtime: {}, process: {},
          container: { envVars: [], mounts: [], capabilities: [], readonlyRootfs: true, noNewPrivileges: true },
          security: { cgroupCPUQuota: quota, cgroupPIDsLimit: "128" },
        }
        : path === "/api/v1/interfaces/state" ? []
        : path === "/api/v1/flows" ? []
        : path === "/api/v1/config/diff" ? { changed: false, changedSections: [] }
        : {};
      await route.fulfill({ json, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
    });
    await page.goto("/topology/");
    await page.getByRole("button", { name: "PHYSICAL", exact: true }).click();
    await page.getByRole("button", { name: "Container runtime details", exact: true }).click();
    const row = page.locator('[class*="resRow"]').filter({ has: page.getByText("CPU quota", { exact: true }) });
    await expect(row).toContainText(quota || "—");
    await expect(row).toBeVisible();
    await expect(row.locator('[class*="resBar"]')).toHaveCount(0);
    await expect(row).toContainText("Configured limit, not CPU usage");
  });
}
