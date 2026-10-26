import { expect, test } from "@playwright/test";

// The rule editor sends a PATCH, which keeps every omitted key: a field the
// user clears must be sent with its empty value to be cleared.

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };
const rule = {
  id: "plc-write",
  description: "Engineering writes",
  action: "ALLOW",
  log: true,
  sourceZones: ["it"],
  destZones: ["ot"],
  sources: ["10.10.0.5/32"],
  destinations: ["10.20.0.7/32"],
  protocols: [{ name: "tcp", port: "502" }],
  ics: { protocol: "modbus", functionCode: [16], mode: "enforce" },
};

test("clearing rule fields in the editor clears them", async ({ page }) => {
  const patches: unknown[] = [];
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/firewall/rules/plc-write" && request.method() === "PATCH") {
      patches.push(request.postDataJSON());
      await route.fulfill({ json: rule });
      return;
    }
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/firewall/rules") body = [rule];
    if (path === "/api/v1/zones") body = [{ name: "it" }, { name: "ot" }];
    if (path === "/api/v1/routing") body = { gateways: [], routes: [], rules: [] };
    if (path === "/api/v1/dataplane") body = { captureInterfaces: [], dpiMock: false };
    await route.fulfill({ json: body });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/firewall/rules");
  await page.goto("/firewall/");
  await loaded;

  await page.getByRole("button", { name: "Edit", exact: true }).click();
  // The create form below repeats these fields; act in the editor only.
  const editor = page.locator("div.fixed").filter({ has: page.getByRole("heading", { name: "Edit rule plc-write" }) });
  await editor.getByPlaceholder("description").fill("");
  await editor.getByLabel("Log hits").uncheck();
  await editor.locator("select").filter({ hasText: "Source zone (any)" }).selectOption("");
  await editor.locator("select").filter({ hasText: "Dest zone (any)" }).selectOption("");
  await editor.getByPlaceholder("sources CIDR (csv)").fill("");
  await editor.getByPlaceholder("destinations CIDR (csv)").fill(" ");
  await editor.getByLabel("ICS Protocol Filter").uncheck();
  await editor.getByRole("button", { name: "Save changes" }).click();

  await expect.poll(() => patches.length).toBe(1);
  expect(patches[0]).toEqual({
    description: "",
    action: "ALLOW",
    log: false,
    sourceZones: [],
    destZones: [],
    sources: [],
    destinations: [],
    protocols: [{ name: "tcp", port: "502" }],
    ics: null,
  });
});
