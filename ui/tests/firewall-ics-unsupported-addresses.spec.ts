import { expect, test, type Page } from "@playwright/test";

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };
const unsupportedAddresses =
  "Address filters are not supported for DNP3 or CIP. Remove this filter before saving; protocol-specific station, point and CIP path selectors are not available yet.";

function rule(protocol: string, addresses?: string[]) {
  return {
    id: "firewall-ics-address-rule",
    description: "ICS address rule",
    action: "DENY",
    log: false,
    sourceZones: ["it"],
    destZones: ["ot"],
    sources: [],
    destinations: [],
    protocols: [{ name: "tcp", port: protocol === "dnp3" ? "20000" : protocol === "cip" ? "44818" : "502" }],
    identities: [],
    ics: { protocol, ...(addresses ? { addresses } : {}) },
  };
}

async function openFirewall(
  page: Page,
  rules: ReturnType<typeof rule>[],
  dataplane: Record<string, unknown> = {},
) {
  const patches: unknown[] = [];
  const creates: unknown[] = [];
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path.startsWith("/api/v1/firewall/rules/") && request.method() === "PATCH") {
      const patch = request.postDataJSON() as Record<string, unknown>;
      patches.push(patch);
      await route.fulfill({ json: { ...rules[0], ...patch } });
      return;
    }
    if (path === "/api/v1/firewall/rules" && request.method() === "POST") {
      const created = request.postDataJSON();
      creates.push(created);
      await route.fulfill({ json: created });
      return;
    }
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/firewall/rules") body = rules;
    if (path === "/api/v1/zones") body = [{ name: "it" }, { name: "ot" }];
    if (path === "/api/v1/routing") body = { gateways: [], routes: [], rules: [] };
    if (path === "/api/v1/dataplane") body = { captureInterfaces: [], dpiMock: false, dpiMode: "learn", ...dataplane };
    await route.fulfill({ json: body });
  });
  const loaded = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/v1/firewall/rules");
  await page.goto("/firewall/");
  await loaded;
  return { patches, creates };
}

function editForm(page: Page) {
  return page.locator("div.fixed").filter({ has: page.getByRole("heading", { name: "Edit rule firewall-ics-address-rule" }) });
}

function createForm(page: Page) {
  return page.locator("section").filter({ has: page.getByRole("heading", { name: "Create rule" }) });
}

function icsProtocolSelect(form: ReturnType<typeof createForm>) {
  return form.getByText("ICS Protocol", { exact: true }).locator("xpath=..").locator("select");
}

for (const protocol of ["dnp3", "cip"]) {
  test(`${protocol} firewall editor displays and clears a stored address filter`, async ({ page }) => {
    const { patches } = await openFirewall(page, [rule(protocol, ["10-20", "30"])]);
    await page.getByRole("button", { name: "Edit", exact: true }).click();
    const form = editForm(page);

    await expect(form.getByRole("alert")).toHaveText(unsupportedAddresses);
    await expect(form).toContainText("Existing address filter: 10-20, 30");
    await expect(form.getByLabel("Register / coil addresses")).toHaveCount(0);
    await expect(form.getByLabel("CA / IOA")).toHaveCount(0);
    await form.getByRole("button", { name: "Remove address filter" }).click();
    await expect(form.getByRole("alert")).toHaveCount(0);
    await expect(form.getByText(/Existing address filter:/)).toHaveCount(0);

    await form.getByRole("button", { name: "Save changes" }).click();
    await expect.poll(() => patches.length).toBe(1);
    expect(patches[0]).toMatchObject({ ics: { protocol, addresses: null } });
  });

  test(`${protocol} firewall create does not carry an address prefill to a changed protocol`, async ({ page }) => {
    const { creates } = await openFirewall(page, []);
    const form = createForm(page);
    await form.getByLabel("ICS Protocol Filter").check();
    await icsProtocolSelect(form).selectOption(protocol);

    await expect(form.getByLabel("Register / coil addresses")).toHaveCount(0);
    await expect(form.getByRole("alert")).toHaveCount(0);
    await expect(form).not.toContainText("0-100");
    await form.getByPlaceholder("id (e.g. mb-allow)").fill(`new-${protocol}`);
    await form.getByRole("button", { name: "Create rule" }).click();
    await expect.poll(() => creates.length).toBe(1);
    const created = creates[0] as { ics: Record<string, unknown> };
    expect(created.ics.protocol).toBe(protocol);
    expect(Object.hasOwn(created.ics, "addresses")).toBe(false);
  });
}

test("firewall Modbus address input and IEC 104 CA/IOA remain available", async ({ page }) => {
  await openFirewall(page, []);
  const form = createForm(page);
  await form.getByLabel("ICS Protocol Filter").check();
  await expect(form.getByLabel("Register / coil addresses")).toBeVisible();
  await icsProtocolSelect(form).selectOption("iec104");
  await expect(form.getByPlaceholder("1", { exact: true })).toBeVisible();
  await expect(form.getByPlaceholder("2001, 65536-65567")).toBeVisible();
});

test("DPI decoder settings no longer advertise DNP3 or CIP address selectors", async ({ page }) => {
  await openFirewall(page, [], { dpiEnabled: true });
  await page.getByText("ICS Protocol Decoders", { exact: true })
    .locator("xpath=../..")
    .getByRole("button", { name: "Configure", exact: true })
    .click();
  const modal = page.locator("div.fixed").filter({ has: page.getByRole("heading", { name: "ICS Protocol DPI Configuration" }) });

  await modal.getByText("DNP3", { exact: true }).click();
  await expect(modal.getByText("Point indices", { exact: true })).toHaveCount(0);
  await expect(modal.getByText("Station addresses", { exact: true })).toHaveCount(0);
  await modal.getByText("CIP / EtherNet/IP", { exact: true }).click();
  await expect(modal.getByText("CIP path", { exact: true })).toHaveCount(0);

  await modal.getByText("Modbus/TCP", { exact: true }).click();
  await expect(modal.getByText("Register/coil addresses", { exact: true })).toBeVisible();
  await modal.getByText("IEC 60870-5-104", { exact: true }).click();
  await expect(modal.getByText("CA and IOA", { exact: true })).toBeVisible();
});
