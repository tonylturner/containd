import { expect, test } from "@playwright/test";
const token = (n: number) => `0123456789abcdef.${n}`;

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
      : path === "/config/diff" ? { changed: false, changedSections: [], running: {}, candidate: {} }
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
