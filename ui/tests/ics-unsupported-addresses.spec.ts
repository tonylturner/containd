import { expect, test, type Page } from "@playwright/test";

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };
const unsupportedAddresses =
  "Address filters are not supported for DNP3 or CIP. Remove this filter before saving; protocol-specific station, point and CIP path selectors are not available yet.";

function rule(protocol: string, addresses?: string[]) {
  return {
    id: "ics-address-rule",
    action: "DENY",
    sourceZones: ["it"],
    destZones: ["ot"],
    protocols: [{ name: "tcp", port: protocol === "dnp3" ? "20000" : protocol === "cip" ? "44818" : "502" }],
    ics: { protocol, ...(addresses ? { addresses } : {}) },
  };
}

async function openICS(page: Page, storedRule: ReturnType<typeof rule>) {
  const patches: unknown[] = [];
  let stored = storedRule;
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/firewall/rules/ics-address-rule" && request.method() === "PATCH") {
      const patch = request.postDataJSON() as { ics: Record<string, unknown> };
      patches.push(patch);
      stored = { ...stored, ics: { ...stored.ics, ...patch.ics } };
      await route.fulfill({ json: stored });
      return;
    }
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/firewall/rules") body = [stored];
    if (path === "/api/v1/dataplane") body = { captureInterfaces: [], dpiMock: false, dpiMode: "learn" };
    if (path === "/api/v1/health") body = { status: "ok", component: "mgmt" };
    await route.fulfill({ json: body });
  });
  const loaded = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/v1/firewall/rules");
  await page.goto("/ics/");
  await loaded;
  return patches;
}

function editor(page: Page) {
  return page.locator("div.fixed").filter({ has: page.getByRole("heading", { name: "ICS filter — rule ics-address-rule" }) });
}

for (const protocol of ["dnp3", "cip"]) {
  test(`${protocol} ICS editor displays and clears a stored address filter`, async ({ page }) => {
    const patches = await openICS(page, rule(protocol, ["10-20", "30"]));
    await page.getByRole("button", { name: "Edit", exact: true }).click();
    const form = editor(page);

    await expect(form.getByRole("alert")).toHaveText(unsupportedAddresses);
    await expect(form).toContainText("Existing address filter: 10-20, 30");
    await expect(form.getByLabel("Register / coil addresses")).toHaveCount(0);
    await expect(form.getByLabel("CA / IOA")).toHaveCount(0);
    await form.getByRole("button", { name: "Remove address filter" }).click();
    await expect(form.getByRole("alert")).toHaveCount(0);
    await expect(form.getByText(/Existing address filter:/)).toHaveCount(0);

    await form.getByRole("button", { name: "Save filter" }).click();
    await expect.poll(() => patches.length).toBe(1);
    expect(patches[0]).toMatchObject({ ics: { protocol, addresses: null } });
    await expect(page.getByText("ICS filter staged — commit to apply.")).toBeVisible();
  });

  test(`${protocol} ICS editor does not prefill addresses when changing protocol`, async ({ page }) => {
    await openICS(page, rule("modbus"));
    await page.getByRole("button", { name: "Edit", exact: true }).click();
    const form = editor(page);
    const protocolSelect = form.locator("select").first();

    await expect(form.getByLabel("Register / coil addresses")).toHaveValue("");
    await protocolSelect.selectOption(protocol);
    await expect(form.getByLabel("Register / coil addresses")).toHaveCount(0);
    await expect(form.getByRole("alert")).toHaveCount(0);
    await expect(form).not.toContainText("0-100");
  });
}

test("Modbus address input and IEC 104 CA/IOA fields remain available", async ({ page }) => {
  await openICS(page, rule("modbus"));
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  const form = editor(page);
  await expect(form.getByLabel("Register / coil addresses")).toBeVisible();
  await form.locator("select").first().selectOption("iec104");
  await expect(form.getByPlaceholder("1", { exact: true })).toBeVisible();
  await expect(form.getByPlaceholder("2001, 65536-65567")).toBeVisible();
});
