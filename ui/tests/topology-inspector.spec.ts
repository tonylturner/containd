import { securityChecks } from "./fixtures/security";
import { expect, test } from "./fixtures/topology-test";

test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/**", async route => {
    const path = new URL(route.request().url()).pathname;
    const data: Record<string, unknown> = {
      "/api/v1/config/running": { interfaces: [] },
      "/api/v1/config": { zones: [{ name: "wan" }, { name: "ot" }], interfaces: [], firewall: { rules: [] } },
      "/api/v1/config/diff": { changed: false, changedSections: [] },
      "/api/v1/interfaces/state": [],
      "/api/v1/flows": [],
      "/api/v1/zones": [{ name: "wan", slTarget: 1 }, { name: "ot", slTarget: 2 }],
      "/api/v1/security/conduits": [{
        from: "wan", to: "ot", state: "allow", ids: "disabled", checks: securityChecks, proto: [{ n: "tcp", t: "allowed" }],
        traffic: { state: "measured" as const, windowSeconds: 3600, bytes: "0", packets: "0", complete: true, coverage: "routed" as const }, rules: ["allow-test"],
        gaps: ["Heuristic (service ports): ICS traffic mixed with plaintext IT protocols"],
        mitre: ["Heuristic (source zone name): T1190 Exploit Public App", "Heuristic (source zone name): T1595 Active Scanning"],
      }],
      "/api/v1/system/inspection": {
        host: { os: "Linux", kernel: "6.1", arch: "arm64", numCPU: 2 }, runtime: { dockerVersion: "27" },
        process: { goVersion: "go1.26", fdCount: 40, fdSoftLimit: 1024, fdHardLimit: 4096 },
        container: { envVars: [{ key: "TEST_RUNTIME", value: "example" }], mounts: [{ hostPath: "/host/certs", containerPath: "/certs", mode: "ro" }], capabilities: ["CAP_NET_ADMIN"], privileged: true, readonlyRootfs: true, noNewPrivileges: true },
        security: { cgroupCPUQuota: "50000 100000", cgroupPIDsLimit: "128" },
      },
    };
    const json = path.includes("/auth/") ? { id: "admin", username: "containd", role: "admin" } : data[path] ?? {};
    await route.fulfill({ json, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
});

test("Physical inspector supports keyboard selection and retains foreground flags when closed at 390px", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/topology/");
  await page.getByRole("button", { name: "PHYSICAL", exact: true }).click();
  const layer = page.getByRole("button", { name: "Container runtime details", exact: true });
  await expect(layer).toBeVisible();
  await page.getByRole("button", { name: "Inspect HOST MACHINE", exact: true }).click();
  await expect(page.getByRole("region", { name: "Deployment inspector" }).getByText("6.1", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Container deployment details", exact: true }).click();
  await expect(page.getByRole("region", { name: "Deployment inspector" }).getByText("/host/certs", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Deployment inspector" }).getByText("NET_ADMIN", { exact: true })).toBeVisible();
  await layer.focus();
  await page.keyboard.press("Enter");
  await expect(layer).toHaveAttribute("aria-expanded", "true");
  const inspector = page.getByRole("region", { name: "Deployment inspector", exact: true });
  await expect(inspector.getByText("50000 100000", { exact: true })).toBeVisible();
  await inspector.getByRole("button", { name: "Hide detail panel" }).click();
  await expect(layer).toBeFocused();
  await expect(layer).toHaveAttribute("aria-expanded", "false");
  await expect(page.getByRole("region", { name: "Deployment attention" }).getByText("Running --privileged", { exact: true })).toBeVisible();
  const process = page.getByRole("button", { name: "Application runtime details", exact: true });
  await process.focus();
  await page.keyboard.press("Space");
  await expect(inspector.getByText("TEST_RUNTIME", { exact: true })).toBeVisible();
  await expect(inspector.getByText("go1.26", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test("security gaps and conduit inspector are keyboard reachable with distinct sources", async ({ page }) => {
  await page.goto("/topology/");
  await page.getByRole("button", { name: "SECURITY", exact: true }).click();
  const cell = page.getByRole("button", { name: "Inspect WAN to OT", exact: true });
  await cell.focus();
  await page.keyboard.press("Enter");
  await expect(cell).toHaveAttribute("aria-expanded", "true");
  const inspector = page.getByRole("region", { name: "Conduit details", exact: true });
  await expect(inspector.getByText("Heuristic (service ports): ICS traffic mixed with plaintext IT protocols", { exact: true })).toBeVisible();
  await expect(inspector.getByText("Heuristic (source zone name): T1190 Exploit Public App", { exact: true })).toBeVisible();
  await expect(inspector.getByText("Heuristic (source zone name): T1595 Active Scanning", { exact: true })).toBeVisible();
  await expect(inspector.getByText("Saved target", { exact: true })).toHaveCount(2);
  await expect(inspector.getByText("routed traffic that passed policy, last hour", { exact: true })).toBeVisible();
  await expect(page.getByText("Conduits summarize running policy, not live verification.", { exact: false })).toBeVisible();
  await inspector.getByRole("button", { name: "Hide detail panel" }).click();
  await expect(cell).toBeFocused();
  await expect(page.getByRole("button", { name: "WAN → OT: 1 gap", exact: true })).toBeVisible();
});

test("logical graph node opens its inspector with Enter", async ({ page }) => {
  await page.goto("/topology/");
  const node = page.locator('.react-flow__node[data-id="fw-main"]');
  // ReactFlow attaches nodes hidden until measured; focus() alone does not wait
  // for visibility and can silently leave keyboard focus on the document.
  await expect(node).toBeVisible();
  await node.focus();
  await expect(node).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("region", { name: "Topology inspector", exact: true }).getByText("Policy Rules", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Topology inspector", exact: true }).getByText("Hostname", { exact: true })).toBeVisible();
  await page.getByRole("region", { name: "Topology inspector", exact: true }).getByRole("button", { name: "Hide detail panel" }).click();
  await expect(node).toBeFocused();
});
