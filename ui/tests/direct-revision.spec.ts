import { expect, test } from "@playwright/test";
const token = (n: number) => `0123456789abcdef.${n}`;

test("quick-start conflict offers one review notice without a generic red error", async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("containd.auth.role", "admin"));
  await page.route("**/api/v1/**", async route => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace("/api/v1", "");
    if (request.method() === "POST" && path === "/routing") {
      request.postDataJSON();
      return route.fulfill({ status: 412, json: {
        error: "quick-start conflict detail", code: "config_revision_mismatch", currentRevision: token(2),
      } });
    }
    const json = path.startsWith("/auth/") ? { id: "admin", role: "admin" }
      : path === "/interfaces" ? [{ name: "wan", device: "eth1", zone: "wan" }]
      : path === "/interfaces/state" ? [{ name: "eth1", addrs: ["192.0.2.2/24"] }]
      : path === "/routing" ? { gateways: [], routes: [], rules: [] }
      : path === "/zones" || path === "/firewall/rules" ? []
      : path === "/dataplane" ? { captureInterfaces: [], dpiMock: false }
      : path === "/firewall/nat" ? { enabled: false }
      : path === "/config/diff" ? { pendingConfirm: null, changed: false, changedSections: [], running: {}, candidate: {} }
      : {};
    return route.fulfill({ json, headers: { "X-Containd-Revision": token(1) } });
  });
  await page.goto("/firewall/");
  await page.getByRole("button", { name: "Quick start (LAN→WAN)", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toBeVisible();
  await expect(page.getByText("quick-start conflict detail", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Keep my edits", exact: true }).click();
  await expect(page.getByText("Based on an older view — review, then save again.", { exact: true })).toBeVisible();
  await expect(page.getByText("quick-start conflict detail", { exact: true })).toHaveCount(0);
});

test("two direct DPI saves without a competing writer use each acknowledgement", async ({ page }) => {
  let counter = 1;
  let dp: Record<string, unknown> = { dpiEnabled: true, dpiMode: "monitor", dpiIcsProtocols: { modbus: true } };
  const writes: (string | undefined)[] = [];
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async route => {
    const req = route.request();
    const path = new URL(req.url()).pathname.replace("/api/v1", "");
    if (req.method() === "POST" && path === "/dataplane") {
      const body = req.postDataJSON();
      const revision = req.headers()["x-containd-if-revision"];
      writes.push(revision);
      if (revision !== token(counter)) return route.fulfill({ status: 412, json: { error: "changed", code: "config_revision_mismatch", currentRevision: token(counter) } });
      dp = body;
      counter++;
      return route.fulfill({ json: dp, headers: { "X-Containd-Revision": token(counter), "X-Containd-Config": "staged" } });
    }
    const json = path.startsWith("/auth/") ? { id: "admin", role: "admin" }
      : path === "/zones" || path === "/firewall/rules" ? []
      : path === "/dataplane" ? dp
      : path === "/config/diff" ? { pendingConfirm: null, changed: false, changedSections: [], running: {}, candidate: {} }
      : {};
    return route.fulfill({ json, headers: { "X-Containd-Revision": token(counter) } });
  });
  await page.goto("/firewall/");
  const toggle = page.getByRole("button", { name: "Toggle DPI", exact: true });
  await expect(toggle).toBeEnabled();
  await toggle.click();
  await expect.poll(() => counter).toBe(2);
  await expect(toggle).toBeEnabled();
  await toggle.click();
  await expect.poll(() => writes.length).toBe(2);
  expect(writes).toEqual([token(1), token(2)]);
});

test("a clean DPI refresh overtakes an acknowledgement without losing the refreshed settings", async ({ page }) => {
  let counter = 1;
  let dp: Record<string, unknown> = { dpiEnabled: true, dpiMode: "monitor" };
  let holdReads = false;
  let releaseSave!: () => void;
  let releaseReads!: () => void;
  const saved = new Promise<void>(resolve => { releaseSave = resolve; });
  const reads = new Promise<void>(resolve => { releaseReads = resolve; });
  const writes: { body: Record<string, unknown>; revision?: string }[] = [];
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async route => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace("/api/v1", "");
    if (request.method() === "POST" && path === "/dataplane") {
      const body = request.postDataJSON();
      const revision = request.headers()["x-containd-if-revision"];
      writes.push({ body, revision });
      if (revision !== token(counter)) return route.fulfill({ status: 412, json: { error: "changed", code: "config_revision_mismatch", currentRevision: token(counter) } });
      dp = body;
      const acknowledgedRevision = token(++counter);
      if (writes.length === 1) await saved;
      return route.fulfill({ json: body, headers: { "X-Containd-Revision": acknowledgedRevision, "X-Containd-Config": "staged" } });
    }
    if (holdReads && !path.startsWith("/auth/")) await reads;
    const json = path.startsWith("/auth/") ? { id: "admin", role: "admin" }
      : path === "/dataplane" ? dp
      : path === "/zones" || path === "/firewall/rules" ? []
      : path === "/config/diff" ? { changed: false, changedSections: [], pendingConfirm: null, running: {}, candidate: {} } : {};
    return route.fulfill({ json, headers: { "X-Containd-Revision": token(counter) } });
  });
  try {
    await page.goto("/firewall/");
    const toggle = page.getByRole("button", { name: "Toggle DPI", exact: true });
    await toggle.click();
    await expect.poll(() => counter).toBe(2);
    dp = { dpiEnabled: true, dpiMode: "enforce", dpiProtocols: { http: false } };
    counter++;
    await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:staged")));
    await expect(page.getByLabel("ICS DPI Mode", { exact: true })).toHaveValue("enforce");
    holdReads = true;
    releaseSave();
    await expect(toggle).toBeEnabled();
    await toggle.click();
    await expect.poll(() => writes.length).toBe(2);
    expect(writes[1]).toMatchObject({ revision: token(3), body: { dpiMode: "enforce", dpiProtocols: { http: false } } });
  } finally {
    releaseSave();
    releaseReads();
  }
});
