import { expect, test, type Page } from "@playwright/test";

// Rule updates keep every omitted key, so the ICS editor clears explicitly:
// a disabled filter is `ics: null`, an inherited mode is `ics.mode: null`.

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };
const base = {
  id: "plc-read",
  action: "ALLOW",
  sourceZones: ["it"],
  destZones: ["ot"],
  protocols: [{ name: "tcp", port: "502" }],
};
const withICS = { ...base, ics: { protocol: "modbus", functionCode: [3], readOnly: true, mode: "enforce" } };

test("disabling an ICS filter clears the rule's predicate", async ({ page }) => {
  const patches: unknown[] = [];
  let stored: Record<string, unknown> = withICS;
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/firewall/rules/plc-read" && request.method() === "PATCH") {
      patches.push(request.postDataJSON());
      stored = { ...base, ics: {} };
      await route.fulfill({ json: stored });
      return;
    }
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/firewall/rules") body = [stored];
    if (path === "/api/v1/dataplane") body = { captureInterfaces: [], dpiMock: false, dpiMode: "enforce" };
    if (path === "/api/v1/health") body = { status: "ok", component: "mgmt" };
    await route.fulfill({ json: body });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/firewall/rules");
  await page.goto("/ics/");
  await loaded;

  await page.getByRole("button", { name: "Edit", exact: true }).click();
  await page.getByLabel("Enable ICS protocol filter").uncheck();
  const reloaded = page.waitForResponse(
    (r) => new URL(r.url()).pathname === "/api/v1/firewall/rules" && r.request().method() === "GET",
  );
  await page.getByRole("button", { name: "Save filter" }).click();
  await reloaded;

  expect(patches).toEqual([{ ics: null }]);
  await expect(page.getByText("ICS filter removal staged — commit to apply.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Edit", exact: true })).toHaveCount(0);
});

async function openEditor(page: Page, rule: Record<string, unknown>) {
  const patches: unknown[] = [];
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/firewall/rules/plc-read" && request.method() === "PATCH") {
      patches.push(request.postDataJSON());
      await route.fulfill({ json: rule });
      return;
    }
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/firewall/rules") body = [rule];
    if (path === "/api/v1/dataplane") body = { captureInterfaces: [], dpiMock: false, dpiMode: "monitor" };
    await route.fulfill({ json: body });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/firewall/rules");
  await page.goto("/ics/");
  await loaded;
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  return patches;
}

test("choosing inherit clears a stored safety mode", async ({ page }) => {
  const patches = await openEditor(page, withICS);
  const mode = page.getByLabel("Safety mode");
  await expect(mode).toHaveValue("enforce");
  await mode.selectOption("");
  await expect(mode.locator("option:checked")).toHaveText("Inherit (Monitor (safe))");
  await page.getByRole("button", { name: "Save filter" }).click();
  await expect.poll(() => patches.length).toBe(1);
  expect(patches[0]).toMatchObject({ ics: { protocol: "modbus", functionCode: [3], readOnly: true, mode: null } });
});

test("an inherited safety mode stays unset", async ({ page }) => {
  const patches = await openEditor(page, { ...base, ics: { protocol: "modbus", functionCode: [3] } });
  await expect(page.getByLabel("Safety mode")).toHaveValue("");
  await page.getByRole("button", { name: "Save filter" }).click();
  await expect.poll(() => patches.length).toBe(1);
  const { ics } = patches[0] as { ics: Record<string, unknown> };
  expect(ics).toMatchObject({ protocol: "modbus", functionCode: [3] });
  expect(Object.hasOwn(ics, "mode")).toBe(false);
});
