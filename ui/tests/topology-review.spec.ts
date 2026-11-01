import { expect, test } from "./fixtures/topology-test";

const stats = {
  cpu: { numCPU: 8, usagePercent: 12.5 },
  memory: { totalBytes: 8 * 1073741824, usedBytes: 2 * 1073741824, availableBytes: 6 * 1073741824, usagePercent: 25 },
  disk: { totalBytes: 100 * 1073741824, usedBytes: 40 * 1073741824, availableBytes: 60 * 1073741824, usagePercent: 40 },
  container: { running: true, memLimitBytes: 1073741824 },
  runtime: {}, ruleEval: {},
};
const inspection = {
  host: { os: "Linux", numCPU: 8 }, runtime: {}, process: {},
  container: {
    networkMode: "host", envVars: [{ key: "CONTAIND_AUTH", value: "relaxed" }], mounts: [], capabilities: [],
    readonlyRootfs: true, noNewPrivileges: true,
  },
  security: { cgroupPIDsLimit: "128" },
};

test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/**", async route => {
    const path = new URL(route.request().url()).pathname;
    const json = path.includes("/auth/") ? { id: "admin", username: "containd", role: "admin" }
      : path === "/api/v1/system/stats" ? stats
      : path === "/api/v1/system/inspection" ? inspection
      : path === "/api/v1/config" ? { zones: [], interfaces: [], firewall: { rules: [] } }
      : path === "/api/v1/interfaces/state" || path === "/api/v1/flows" ? []
      : path === "/api/v1/config/diff" ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
});

test("host inspector keeps the original CPU, memory and storage labels with exact values", async ({ page }) => {
  await page.goto("/topology/");
  await page.getByRole("button", { name: "PHYSICAL", exact: true }).click();
  await page.getByRole("button", { name: "Inspect HOST MACHINE", exact: true }).click();
  const inspector = page.getByRole("region", { name: "Deployment inspector" });
  const section = (name: string) => inspector.getByText(name, { exact: true }).locator("..");
  await expect(section("vCPU count")).toHaveText("vCPU count8");
  await expect(section("Current usage")).toHaveText("Current usage12.5%");
  const memory = section("Memory");
  await expect(memory).toContainText("Total RAM8.0 GB");
  await expect(memory).toContainText("Used2.0 GB (25.0%)");
  await expect(memory).toContainText("Available6.0 GB");
  const storage = section("Storage");
  await expect(storage).toContainText("Total100.0 GB");
  await expect(storage).toContainText("Used40.0 GB (40.0%)");
  await expect(storage).toContainText("Available60.0 GB");
});

for (const missing of ["inspection", "stats", "both"] as const) {
  test(`physical unknown badges are neutral when ${missing} is unavailable`, async ({ page }) => {
    for (const endpoint of missing === "both" ? ["inspection", "stats"] : [missing]) {
      await page.route(`**/api/v1/system/${endpoint}`, route => route.fulfill({ status: 503, json: { error: "Unavailable" } }));
    }
    await page.goto("/topology/");
    await page.getByRole("button", { name: "PHYSICAL", exact: true }).click();
    for (const [name, known] of [
      ["Inspect HOST MACHINE", missing === "stats"],
      ["Container runtime details", missing === "stats"],
      ["Container deployment details", missing === "stats"],
      ["Application runtime details", missing === "inspection"],
    ] as const) {
      const badge = page.getByRole("button", { name, exact: true }).getByText(known ? "REPORTED" : "UNKNOWN", { exact: true });
      await expect(badge).toBeVisible();
      await expect(badge).toHaveClass(known ? /badgeOk/ : /badgeUnknown/);
      if (!known) await expect(badge).not.toHaveClass(/badgeOk/);
    }
    if (missing !== "inspection") {
      await page.getByRole("button", { name: "Inspect HOST MACHINE", exact: true }).click();
      const inspector = page.getByRole("region", { name: "Deployment inspector" });
      await expect(inspector.getByText("Current usage", { exact: true }).locator("..")).toHaveText("Current usageUnknown");
      await expect(inspector.getByText("Total RAM", { exact: true }).locator("..")).toHaveText("Total RAMUnknown");
      await expect(inspector.getByText("Resource statistics unavailable.", { exact: true })).toBeVisible();
      await expect(inspector.locator('[class*="resBarWrap"]')).toHaveCount(0);
    }
  });
}

test("physical flags omit undefined authentication settings and explain host loopback exposure", async ({ page }) => {
  await page.goto("/topology/");
  await page.getByRole("button", { name: "PHYSICAL", exact: true }).click();
  const attention = page.getByRole("region", { name: "Deployment attention" });
  await expect(attention.getByText("Host network namespace", { exact: true })).toBeVisible();
  await expect(attention).toContainText("The container shares the host's interfaces and loopback.");
  await expect(attention).toContainText("Loopback listeners are host-wide, not container-private.");
  await expect(attention.getByRole("link", { name: "Threat model", exact: true })).toHaveAttribute("href", "/docs/threat-model/#management-plane-to-dataplane");
  await expect(attention).not.toContainText("CONTAIND_AUTH");
  await expect(attention).not.toContainText("expected for a firewall");
  await page.getByRole("button", { name: "Application runtime details", exact: true }).click();
  await expect(page.getByRole("region", { name: "Deployment inspector" })).toContainText("CONTAIND_AUTH");
});
