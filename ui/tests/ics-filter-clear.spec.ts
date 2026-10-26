import { expect, test } from "@playwright/test";

// Disabling a rule's ICS filter stages its removal: the rule PATCH clears the
// predicate with `ics: null`, because an omitted key keeps the stored one.

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
