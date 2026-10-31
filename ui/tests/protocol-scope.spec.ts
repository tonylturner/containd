import { expect, test, type Page } from "@playwright/test";

const admin = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };
const retained = ["modbus", "dnp3", "iec104", "cip"];
const retired = ["s7comm", "mms", "bacnet", "opcua"];
const supportedLabels = [
  "Modbus/TCP",
  "DNP3",
  "IEC 60870-5-104",
  "CIP / EtherNet/IP",
];

const unsupportedMapError =
  'dataplane.dpiIcsProtocols: protocol "s7comm" is not supported; supported: modbus, dnp3, iec104, cip';

const legacyRule = {
  id: "legacy-s7-rule",
  description: "Historical unsupported rule",
  action: "ALLOW",
  protocols: [{ name: "tcp", port: "102" }],
  ics: { protocol: "s7comm", functionCode: [4] },
};

type MockOptions = {
  rules?: unknown[];
  dataplane?: Record<string, unknown>;
  templates?: unknown[];
  events?: unknown[];
  setDataPlaneStatus?: number;
};

async function mockAPI(page: Page, options: MockOptions = {}) {
  const seen = { dataPlanePosts: [] as Record<string, unknown>[] };
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const method = request.method();

    if (path === "/api/v1/dataplane" && method === "POST") {
      const body = request.postDataJSON() as Record<string, unknown>;
      seen.dataPlanePosts.push(body);
      if (options.setDataPlaneStatus === 400 && seen.dataPlanePosts.length === 1) {
        await route.fulfill({
          status: 400,
          contentType: "application/json",
          body: JSON.stringify({ error: unsupportedMapError }),
        });
      } else {
        await route.fulfill({ json: body });
      }
      return;
    }
    if (path.startsWith("/api/v1/firewall/rules/") && method === "DELETE") {
      await route.fulfill({ status: 200, json: {} });
      return;
    }

    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = admin;
    if (path === "/api/v1/config/diff") body = { changed: false, changedSections: [] };
    if (path === "/api/v1/firewall/rules") body = options.rules ?? [];
    if (path === "/api/v1/dataplane") {
      body = options.dataplane ?? { captureInterfaces: [], dpiMock: false, dpiEnabled: true };
    }
    if (path === "/api/v1/dataplane/ics-coverage") body = { candidate: [], applied: [] };
    if (path === "/api/v1/dataplane/ruleset/status") body = { installed: true };
    if (path === "/api/v1/dataplane/ruleset") body = {};
    if (path === "/api/v1/health") body = { status: "ok", component: "mgmt" };
    if (path === "/api/v1/zones") body = [{ name: "it" }, { name: "ot" }, { name: "wan" }];
    if (path === "/api/v1/routing") body = { gateways: [], routes: [], rules: [] };
    if (path === "/api/v1/firewall/nat") body = { enabled: false };
    if (path === "/api/v1/firewall/counters") body = {};
    if (path === "/api/v1/templates/ics") body = options.templates ?? [];
    if (path === "/api/v1/events") body = options.events ?? [];
    await route.fulfill({ json: body });
  });
  return seen;
}

async function openAndWait(page: Page, path: string, endpoints: string[]) {
  const responses = endpoints.map((endpoint) =>
    page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname === endpoint &&
        response.request().method() === "GET",
    ),
  );
  await page.goto(path);
  await Promise.all(responses);
}

test("firewall rule form offers only the four supported industrial protocols", async ({ page }) => {
  await mockAPI(page);
  await openAndWait(page, "/firewall/", [
    "/api/v1/firewall/rules",
    "/api/v1/dataplane",
    "/api/v1/zones",
  ]);

  const createForm = page.locator("section").filter({
    has: page.getByRole("heading", { name: "Create rule" }),
  });
  await createForm.getByLabel("ICS Protocol Filter").check();
  const selector = createForm
    .getByText("ICS Protocol", { exact: true })
    .locator("..")
    .locator("select");
  const options = await selector.locator("option").evaluateAll((items) =>
    items.map((item) => (item as HTMLOptionElement).value),
  );
  expect(options).toEqual(retained);
  for (const name of retired) expect(options).not.toContain(name);
  const optionLabels = await selector.locator("option").allTextContents();
  for (const label of supportedLabels) expect(optionLabels.join(" ")).toContain(label);
});

test("decoder toggles list only supported protocols and preserve unsupported keys until explicitly removed", async ({ page }) => {
  const seen = await mockAPI(page, {
    dataplane: {
      captureInterfaces: [],
      dpiMock: false,
      dpiEnabled: true,
      dpiIcsProtocols: { s7comm: false },
    },
    setDataPlaneStatus: 400,
  });
  await openAndWait(page, "/firewall/", [
    "/api/v1/firewall/rules",
    "/api/v1/dataplane",
    "/api/v1/zones",
  ]);

  const configure = page.getByRole("button", { name: "Configure", exact: true }).first();
  await configure.click();
  let modal = page.locator("div.fixed.inset-0").filter({
    has: page.getByRole("heading", { name: "ICS Protocol DPI Configuration" }),
  });
  const supportedRows = modal.locator("div.space-y-1");
  for (const label of supportedLabels) await expect(supportedRows).toContainText(label);
  for (const name of retired) await expect(supportedRows).not.toContainText(name);
  await expect(modal).toContainText("s7comm");
  await expect(modal).toContainText("unsupported");

  await modal.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText(`Not saved: ${unsupportedMapError}`)).toBeVisible();
  expect(seen.dataPlanePosts[0]?.dpiIcsProtocols).toEqual({ s7comm: false });

  // A rejected save keeps the editor open with the draft.
  await expect(modal).toBeVisible();
  await expect(modal).toContainText("s7comm");
  await modal.getByRole("button", { name: "Remove unsupported protocol s7comm" }).click();
  await modal.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => seen.dataPlanePosts.length).toBe(2);
  expect(seen.dataPlanePosts[1]?.dpiIcsProtocols).toEqual({});
});

test("ICS page choices contain all four protocols without retired choices", async ({ page }) => {
  await mockAPI(page, {
    rules: retained.map((protocol) => ({
      id: `rule-${protocol}`,
      action: "ALLOW",
      ics: { protocol },
    })),
  });
  await openAndWait(page, "/ics/", [
    "/api/v1/firewall/rules",
    "/api/v1/dataplane",
    "/api/v1/dataplane/ics-coverage",
    "/api/v1/health",
    "/api/v1/dataplane/ruleset/status",
  ]);

  const summary = page.locator('section[aria-label="Supported Protocols"]');
  for (const label of supportedLabels) await expect(summary).toContainText(label);
  for (const label of ["S7comm", "IEC 61850 MMS", "BACnet/IP", "OPC UA"]) {
    await expect(summary).not.toContainText(label);
  }
  const tabs = page.getByRole("button", { name: "All", exact: true }).locator("..");
  for (const label of supportedLabels) await expect(tabs).toContainText(label);
  for (const label of ["S7comm", "IEC 61850 MMS", "BACnet/IP", "OPC UA"]) {
    await expect(tabs).not.toContainText(label);
  }
});

test("unsupported saved rules render raw and read-only, with delete available", async ({ page }) => {
  await mockAPI(page, { rules: [legacyRule] });
  await openAndWait(page, "/firewall/", [
    "/api/v1/firewall/rules",
    "/api/v1/dataplane",
    "/api/v1/zones",
  ]);
  const row = page.getByRole("row").filter({ hasText: "legacy-s7-rule" });
  await expect(row).toContainText("s7comm");
  await expect(row).toContainText("unsupported");
  await expect(row).not.toContainText("Modbus/TCP");
  await expect(row).toContainText("Read-only");
  await expect(row.getByRole("button", { name: "Edit", exact: true })).toHaveCount(0);
  const remove = page.waitForResponse(
    (response) =>
      new URL(response.url()).pathname === "/api/v1/firewall/rules/legacy-s7-rule" &&
      response.request().method() === "DELETE",
  );
  await row.getByRole("button", { name: "Delete", exact: true }).click();
  await page.getByRole("button", { name: "Delete", exact: true }).last().click();
  await remove;
});

test("wizard ICS choices contain only the four supported protocols", async ({ page }) => {
  await mockAPI(page);
  await openAndWait(page, "/wizard/", ["/api/v1/zones", "/api/v1/firewall/nat"]);
  await page.getByRole("button", { name: /Allow ICS Communication/ }).click();
  const selector = page
    .getByText("ICS Protocol", { exact: true })
    .locator("..")
    .locator("select");
  const options = await selector.locator("option").evaluateAll((items) =>
    items.map((item) => (item as HTMLOptionElement).value),
  );
  expect(options).toEqual(retained);
  for (const name of retired) expect(options).not.toContain(name);
  const optionLabels = await selector.locator("option").allTextContents();
  for (const label of supportedLabels) expect(optionLabels.join(" ")).toContain(label);
});

test("templates use only the four supported protocol names", async ({ page }) => {
  await mockAPI(page, {
    templates: retained.map((protocol) => ({
      name: `template-${protocol}`,
      description: `${protocol} baseline`,
      protocol,
    })),
  });
  await openAndWait(page, "/templates/", ["/api/v1/templates/ics", "/api/v1/zones"]);

  for (const protocol of retained) {
    await expect(page.getByText(protocol, { exact: true })).toBeVisible();
  }
  for (const name of retired) {
    await expect(page.getByText(name, { exact: true })).toHaveCount(0);
  }
});

test("legacy alert attributes keep generic raw rendering instead of retired detail blocks", async ({ page }) => {
  await mockAPI(page, {
    events: [{
      id: "1",
      flowId: "old-flow",
      proto: "ids",
      kind: "alert",
      timestamp: "2026-10-26T12:00:00Z",
      attributes: {
        severity: "high",
        message: "Historical event",
        rule_id: "legacy-alert",
        event_proto: "s7comm",
        event_kind: "read",
        event_attrs: { function_code: 4, area: "DB", marker: "legacy" },
      },
    }],
  });
  await openAndWait(page, "/alerts/", ["/api/v1/events"]);
  await page.getByText("Historical event", { exact: true }).click();
  const detail = page.locator("div.sticky").filter({ hasText: "Historical event" });
  await expect(detail).toContainText("Event Attributes");
  await expect(detail).toContainText("function_code:");
  await expect(detail.getByText("marker:", { exact: true })).toBeVisible();
  await expect(detail.getByText("legacy", { exact: true })).toBeVisible();
  await expect(detail).not.toContainText("S7comm Protocol Analysis");
});
