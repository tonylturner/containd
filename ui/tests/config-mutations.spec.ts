import { expect, test, type Page, type Response } from "@playwright/test";
import type { IDSConfig, IDSRule, VPNConfig } from "../lib/api";
import { CONFIG_STAGED } from "../lib/config-events";

const read = (path: string) => (r: Response) =>
  new URL(r.url()).pathname === `/api/v1${path}` && r.request().method() === "GET";
const row = (page: Page, key: string) =>
  page.getByRole("row").filter({ has: page.getByRole("cell", { name: key, exact: true }) });
const imported: IDSRule = { id: "imported-rule", title: "Imported rule", enabled: true };

async function mockAPI(page: Page) {
  const collections: Record<string, Record<string, unknown>[]> = {
    "/zones": [{ name: "lan" }, { name: "wan" }],
    "/interfaces": [{ name: "lan1" }, { name: "wan1" }],
    "/identities": [
      { ip: "192.0.2.5", identities: ["operator"] },
      { ip: "192.0.2.6", identities: ["historian"] },
    ],
  };
  const server = {
    ids: { enabled: true, rules: [{ id: "existing-rule", title: "Existing rule", enabled: true }] } as IDSConfig,
    saved: null as IDSConfig | null,
    imports: [] as string[],
    collections,
    failImportRead: false,
    failReads: false,
    vpn: { wireguard: { enabled: false, interface: "wg0", peers: [] }, openvpn: { enabled: false } } as VPNConfig,
    savedVPN: null as VPNConfig | null,
    holdNextRead: null as Promise<void> | null,
    readHeld: false,
  };
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname.slice("/api/v1".length);
    const method = req.method();
    let result: unknown = {};
    if (path.startsWith("/auth/")) result = { id: "admin", username: "containd", role: "admin" };
    else if (path === "/ids/import") {
      server.imports.push(req.postData() ?? "");
      server.ids = { ...server.ids, rules: [...server.ids.rules ?? [], imported] };
      server.failReads = server.failImportRead;
      result = { imported: 1, skipped: 0, total: server.ids.rules!.length, format: "suricata" };
    } else if (path === "/ids/rules") {
      if (method === "GET" && server.failReads) return route.fulfill({ status: 503, json: { error: "Unavailable" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
      if (method === "POST") server.saved = server.ids = req.postDataJSON();
      result = server.ids;
    } else if (path === "/interfaces/assign") {
      const { mode } = req.postDataJSON();
      expect(mode).toBe("auto");
      collections["/interfaces"] = collections["/interfaces"].map((item, i) => ({ ...item, device: `eth${i}` }));
      result = { interfaces: collections["/interfaces"] };
    } else if (path === "/ids/convert/sigma") {
      const { sigmaYAML } = req.postDataJSON();
      expect(sigmaYAML).toContain("title:");
      result = { id: "converted", title: "Converted rule", enabled: true };
    } else if (path === "/services/vpn/openvpn/profile") {
      const { name } = req.postDataJSON();
      server.vpn = { ...server.vpn, openvpn: { ...server.vpn.openvpn, configPath: `/data/openvpn/profiles/${name}.ovpn`, managed: undefined } };
      result = { configPath: server.vpn.openvpn?.configPath, vpn: server.vpn };
    } else if (path === "/services/vpn") {
      if (method === "POST") server.savedVPN = server.vpn = req.postDataJSON();
      result = server.vpn;
    } else if (path === "/ids/sources" || path === "/firewall/rules" || path === "/interfaces/state") result = [];
    else {
      const collection = Object.keys(collections).find((key) => path === key || path.startsWith(`${key}/`));
      if (collection) {
        const key = collection === "/identities" ? "ip" : "name";
        if (method === "DELETE") {
          const id = decodeURIComponent(path.slice(collection.length + 1));
          collections[collection] = collections[collection].filter((item) => item[key] !== id);
        } else if (method === "POST" || method === "PATCH") {
          const body = req.postDataJSON();
          const id = method === "PATCH" ? decodeURIComponent(path.slice(collection.length + 1)) : body[key];
          const previous = collections[collection].find((item) => item[key] === id);
          result = { ...previous, ...body };
          collections[collection] = [...collections[collection].filter((item) => item[key] !== id), result as Record<string, unknown>];
        } else result = collection === "/identities" ? { mappings: collections[collection] } : collections[collection];
      }
    }
    if (path === "/ids/rules" && method === "GET" && server.holdNextRead) {
      const hold = server.holdNextRead;
      server.holdNextRead = null;
      server.readHeld = true;
      await hold;
    }
    await route.fulfill({ json: result, headers: { "X-Containd-Revision": "0123456789abcdef.1", ...(method === "GET" || path === "/ids/convert/sigma" ? {} : { "X-Containd-Config": "staged" }) } });
  });
  return server;
}

async function importFile(page: Page) {
  await page.getByRole("button", { name: "Import", exact: true }).click();
  await page.locator("#ids-import select").selectOption("suricata");
  await page.locator('input[type="file"]').setInputFiles({
    name: "test.rules", mimeType: "text/plain",
    buffer: Buffer.from('alert tcp any any -> any any (msg:"Imported rule"; sid:10001;)\n'),
  });
  await page.getByRole("button", { name: "Import", exact: true }).last().click();
}

test("IDS explicit format import appears and Save cannot delete it with no rule edits", async ({ page }) => {
  const server = await mockAPI(page);
  await Promise.all([page.waitForResponse(read("/ids/rules")), page.goto("/ids/")]);
  await expect(row(page, "existing-rule")).toBeVisible();
  await importFile(page);
  await expect.soft(row(page, "imported-rule")).toBeVisible();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => server.saved?.rules).toContainEqual(imported);
  expect(server.imports[0]).toContain("suricata");
});

test("IDS import joins a pending rule edit in the visible draft and Save payload", async ({ page }) => {
  const server = await mockAPI(page);
  await Promise.all([page.waitForResponse(read("/ids/rules")), page.goto("/ids/")]);
  await row(page, "existing-rule").getByTitle("Click to disable", { exact: true }).click();
  await importFile(page);
  await expect(row(page, "imported-rule")).toBeVisible();
  await expect(row(page, "existing-rule").getByTitle("Click to enable", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => server.saved?.rules).toEqual([
    { id: "existing-rule", title: "Existing rule", enabled: false }, imported,
  ]);
});

for (const item of [
  { name: "Zones", path: "/zones", first: "lan", second: "wan", created: "dmz", create: "Create", remove: "Delete" },
  { name: "Interfaces", path: "/interfaces", first: "lan1", second: "wan1", created: "dmz1", create: "Create", remove: "Delete" },
  { name: "Identities", path: "/identities", first: "192.0.2.5", second: "192.0.2.6", created: "192.0.2.9", create: "Bind", remove: "Remove" },
]) {
  for (const mutation of ["creates", "deletes"]) {
    test(`${item.name} ${mutation} another row while an unrelated edit is pending`, async ({ page }) => {
      await mockAPI(page);
      await Promise.all([page.waitForResponse(read(item.path)), page.goto(`${item.path}/`)]);
      const pending = row(page, item.first);
      await pending.getByRole("button", { name: "Edit", exact: true }).click();
      const field = pending.getByRole("textbox").first();
      await field.fill("pending edit");
      if (mutation === "creates") {
        if (item.name === "Identities") {
          await page.getByLabel("Address", { exact: true }).fill(item.created);
          await page.getByLabel("Identities", { exact: true }).fill("vendor");
        } else {
          await page.getByPlaceholder(item.name === "Zones" ? "name (e.g. ot)" : "name (e.g. tunnel1)").fill(item.created);
        }
        await page.getByRole("button", { name: item.create, exact: true }).click();
        await expect(row(page, item.created)).toBeVisible();
      } else {
        await row(page, item.second).getByRole("button", { name: "Delete", exact: true }).click();
        if (item.name !== "Interfaces") await page.getByRole("dialog").getByRole("button", { name: item.remove, exact: true }).click();
        await expect(row(page, item.second)).toHaveCount(0);
      }
      await expect(field).toHaveValue("pending edit");
      // The next subscription read must not bring an acknowledged deletion back.
      await Promise.all([
        page.waitForResponse(read(item.path)),
        page.evaluate((event) => window.dispatchEvent(new CustomEvent(event)), CONFIG_STAGED),
      ]);
      await expect(field).toHaveValue("pending edit");
      await expect(row(page, mutation === "creates" ? item.created : item.second)).toHaveCount(mutation === "creates" ? 1 : 0);
    });
  }

  test(`${item.name} creation fields do not block collection adoption`, async ({ page }) => {
    const server = await mockAPI(page);
    await Promise.all([page.waitForResponse(read(item.path)), page.goto(`${item.path}/`)]);
    const field = item.name === "Identities" ? page.getByLabel("Identities", { exact: true })
      : page.getByPlaceholder(item.name === "Zones" ? "name (e.g. ot)" : "name (e.g. tunnel1)");
    await field.fill("unfinished, ");
    server.collections[item.path].push(item.name === "Identities"
      ? { ip: item.created, identities: ["vendor"] } : { name: item.created });
    await Promise.all([
      page.waitForResponse(read(item.path)),
      page.evaluate((event) => window.dispatchEvent(new CustomEvent(event)), CONFIG_STAGED),
    ]);
    await expect(row(page, item.created)).toBeVisible();
    await expect(field).toHaveValue("unfinished, ");
  });
}

test("IDS import and group creation forms never dirty the configuration or block adoption", async ({ page }) => {
  const server = await mockAPI(page);
  await Promise.all([page.waitForResponse(read("/ids/rules")), page.goto("/ids/")]);
  await page.getByRole("button", { name: /^Groups/ }).click();
  await page.getByPlaceholder("e.g. ICS/Modbus").fill("unfinished group");
  await page.getByRole("button", { name: "Import", exact: true }).click();
  await page.locator("#ids-import select").selectOption("suricata");
  await page.locator("textarea").fill("unfinished sigma");
  await page.locator('input[type="file"]').setInputFiles({
    name: "test.rules", mimeType: "text/plain", buffer: Buffer.from("unfinished"),
  });
  server.ids = { ...server.ids, enabled: false, rules: [...server.ids.rules ?? [], imported] };
  await Promise.all([
    page.waitForResponse(read("/ids/rules")),
    page.evaluate((event) => window.dispatchEvent(new CustomEvent(event)), CONFIG_STAGED),
  ]);
  await expect(page.getByRole("checkbox", { name: "Enable intrusion detection" })).not.toBeChecked();
  await expect(page.getByRole("status", { name: "Unsaved edits" })).toHaveCount(0);
  await expect(page.locator("#ids-import select")).toHaveValue("suricata");
  await expect(page.locator("textarea")).toHaveValue("unfinished sigma");
  await page.getByRole("button", { name: /^Rules/ }).click();
  await expect(row(page, "imported-rule")).toBeVisible();
  await expect(page.getByRole("button", { name: /^Groups/ })).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByPlaceholder("e.g. ICS/Modbus")).toHaveValue("unfinished group");
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByPlaceholder("e.g. ICS/Modbus")).toHaveValue("");
});

test("IDS blocks Save after an acknowledged import until its rules can be read", async ({ page }) => {
  const server = await mockAPI(page);
  await Promise.all([page.waitForResponse(read("/ids/rules")), page.goto("/ids/")]);
  await row(page, "existing-rule").getByTitle("Click to disable", { exact: true }).click();
  let release!: () => void;
  server.holdNextRead = new Promise<void>((resolve) => { release = resolve; });
  await page.evaluate((event) => window.dispatchEvent(new CustomEvent(event)), CONFIG_STAGED);
  await expect.poll(() => server.readHeld).toBe(true);
  server.failImportRead = true;
  await importFile(page);
  await expect(page.getByText("Changes saved, but the latest settings could not be loaded. Reload before saving again.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Save", exact: true })).toBeDisabled();
  // Releasing a pre-import snapshot must not acknowledge the import or enable Save.
  const stale = page.waitForResponse((r) => read("/ids/rules")(r) && r.status() === 200);
  release();
  await stale;
  await expect(page.getByRole("button", { name: "Save", exact: true })).toBeDisabled();
  server.failReads = false;
  await Promise.all([
    page.waitForResponse(read("/ids/rules")),
    page.evaluate((event) => window.dispatchEvent(new CustomEvent(event)), CONFIG_STAGED),
  ]);
  await expect(row(page, "imported-rule")).toBeVisible();
  await expect(page.getByRole("button", { name: "Save", exact: true })).toBeEnabled();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => server.saved?.rules).toEqual([
    { id: "existing-rule", title: "Existing rule", enabled: false }, imported,
  ]);
});

test("interface auto-assignment acknowledges devices while another row edit is pending", async ({ page }) => {
  await mockAPI(page);
  await Promise.all([page.waitForResponse(read("/interfaces")), page.goto("/interfaces/")]);
  await row(page, "lan1").getByRole("button", { name: "Edit", exact: true }).click();
  const alias = row(page, "lan1").getByPlaceholder("alias (optional)");
  await alias.fill("pending alias");
  await page.getByRole("button", { name: "Auto-assign", exact: true }).click();
  await expect(row(page, "wan1")).toContainText("eth1");
  await expect(alias).toHaveValue("pending alias");
});

test("Sigma conversion adds a local rule without acknowledging unrelated rule edits", async ({ page }) => {
  const server = await mockAPI(page);
  await Promise.all([page.waitForResponse(read("/ids/rules")), page.goto("/ids/")]);
  await row(page, "existing-rule").getByTitle("Click to disable", { exact: true }).click();
  await page.getByRole("button", { name: "Import", exact: true }).click();
  await page.locator("textarea").fill("title: Converted rule");
  await page.getByRole("button", { name: "Convert & Add", exact: true }).click();
  await expect(row(page, "converted")).toBeVisible();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => server.saved?.rules).toEqual([
    { id: "existing-rule", title: "Existing rule", enabled: false },
    { id: "converted", title: "Converted rule", enabled: true },
  ]);
});

test("VPN profile import acknowledges its path while retaining unrelated WireGuard text", async ({ page }) => {
  const server = await mockAPI(page);
  await Promise.all([page.waitForResponse(read("/services/vpn")), page.goto("/vpn/")]);
  await page.getByText("Advanced peer settings", { exact: true }).click();
  const peers = page.getByRole("textbox", { name: /^Peers \(JSON\)/ });
  await peers.fill('[{"publicKey":"pending","allowedIPs":["192.0.2.0/24"]}] ');
  await page.getByText("Advanced profile import", { exact: true }).click();
  await page.locator('input[type="file"]').setInputFiles({
    name: "imported.ovpn", mimeType: "text/plain", buffer: Buffer.from("client\nremote vpn.example\n"),
  });
  await expect(page.getByPlaceholder("/data/openvpn/profiles/client.ovpn")).toBeVisible();
  await expect(page.getByPlaceholder("/data/openvpn/profiles/client.ovpn")).toHaveValue("/data/openvpn/profiles/imported.ovpn");
  await expect(peers).toHaveValue('[{"publicKey":"pending","allowedIPs":["192.0.2.0/24"]}] ');
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => server.savedVPN).toMatchObject({
    wireguard: { peers: [{ publicKey: "pending", allowedIPs: ["192.0.2.0/24"] }] },
    openvpn: { configPath: "/data/openvpn/profiles/imported.ovpn" },
  });
});

for (const scenario of [
  { name: "saved disabled OpenVPN profile path opens by default", enabled: false, configPath: "/data/openvpn/profiles/saved.ovpn", open: true },
  { name: "enabled path-based OpenVPN client reveals its required path", enabled: true, configPath: "", open: true },
  { name: "unused empty OpenVPN profile path stays available in its disclosure", enabled: false, configPath: "", open: false },
]) {
  test(scenario.name, async ({ page }) => {
    const server = await mockAPI(page);
    server.vpn.openvpn = { enabled: scenario.enabled, mode: "client", configPath: scenario.configPath };
    await Promise.all([page.waitForResponse(read("/services/vpn")), page.goto("/vpn/")]);
    const path = page.getByPlaceholder("/data/openvpn/profiles/client.ovpn");
    const disclosure = page.locator("details").filter({ has: path });
    if (scenario.open) {
      await expect(disclosure).toHaveAttribute("open", "");
      await expect(path).toBeVisible();
    } else {
      await expect(path).not.toBeVisible();
      await disclosure.locator("summary").click();
      await expect(path).toBeVisible();
    }
    await expect(path).toHaveValue(scenario.configPath);
    expect(server.savedVPN).toBeNull();
  });
}
