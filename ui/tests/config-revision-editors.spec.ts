import { expect, test, type Page } from "@playwright/test";

async function setup(page: Page) {
  const state = { counter: 1, writes: [] as { path: string; revision?: string; body: any }[], zones: [{ name: "one", alias: "" }, { name: "two", alias: "" }] };
  const revision = () => `0123456789abcdef.${state.counter}`;
  const rule = { id: "ot-rule", action: "ALLOW", description: "Original", ics: { protocol: "modbus", functionCode: [3], mode: "monitor" } };
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async route => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace("/api/v1", "");
    const headers = { "X-Containd-Revision": revision() };
    if (request.method() === "GET") {
      const data: Record<string, unknown> = {
        "/auth/me": { id: "admin", username: "containd", role: "admin" },
        "/auth/session": { id: "admin", username: "containd", role: "admin" },
        "/identities": { mappings: [] }, "/interfaces": [],
        "/ids/rules": { rules: [], ruleGroups: [] }, "/ids/sources": [],
        "/services/syslog": { forwarders: [] },
        "/services/proxy/forward": {}, "/services/proxy/reverse": { sites: [] },
        "/zones": state.zones, "/firewall/rules": [rule], "/routing": {}, "/firewall/nat": { enabled: false },
        "/dataplane": { dpiMode: "monitor", dpiEnabled: true, dpiIcsProtocols: { modbus: true } },
        "/config/diff": { pendingConfirm: null, changed: false, changedSections: [], running: {}, candidate: {} },
      };
      return route.fulfill({ headers, json: data[path] ?? {} });
    }
    const body = request.postData() ? request.postDataJSON() : undefined;
    const base = request.headers()["x-containd-if-revision"];
    state.writes.push({ path, revision: base, body });
    if (base !== revision()) return route.fulfill({ status: 412, json: { error: "changed", code: "config_revision_mismatch", currentRevision: revision() } });
    state.counter++;
    if (path.startsWith("/zones/")) {
      const row = state.zones.find(z => path.endsWith(z.name))!;
      if (request.method() === "DELETE") state.zones = state.zones.filter(z => z.name !== row.name);
      else Object.assign(row, body);
      return route.fulfill({ headers: { "X-Containd-Revision": revision(), "X-Containd-Config": "staged" }, json: row });
    }
    return route.fulfill({ headers: { "X-Containd-Revision": revision(), "X-Containd-Config": "staged" }, json: path === "/identities" || path === "/interfaces" || path.startsWith("/services/") || path === "/dataplane" ? body : { ...rule, ...body } });
  });
  return state;
}

test("one row acknowledgement advances the shared base without discarding another row's edits", async ({ page }) => {
  const state = await setup(page);
  await page.goto("/zones/");
  const one = page.getByRole("row").filter({ has: page.getByRole("cell", { name: "one", exact: true }) });
  const two = page.getByRole("row").filter({ has: page.getByRole("cell", { name: "two", exact: true }) });
  for (const [row, text] of [[one, "first"], [two, "second"]] as const) {
    await row.getByRole("button", { name: "Edit", exact: true }).click();
    await row.getByRole("textbox").first().fill(text);
  }
  await one.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => state.counter).toBe(2);
  await expect(two.getByRole("textbox").first()).toHaveValue("second");
  await two.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => state.counter).toBe(3);
  expect(state.writes.map(w => w.revision)).toEqual(["0123456789abcdef.1", "0123456789abcdef.2"]);
  await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toHaveCount(0);
});

for (const surface of ["Firewall", "ICS"]) {
  test(`${surface} modal retains a dirty base across refresh and resolves conflict without closing`, async ({ page }) => {
    const state = await setup(page);
    await page.goto(surface === "Firewall" ? "/firewall/" : "/ics/");
    await page.getByRole("row").filter({ hasText: "ot-rule" }).getByRole("button", { name: "Edit", exact: true }).click();
    const input = surface === "Firewall" ? page.getByPlaceholder("sources CIDR (csv)").last() : page.getByPlaceholder("3, 16");
    const raw = surface === "Firewall" ? "192.0.2.0/24, " : "3, ";
    await input.fill(raw);
    state.counter++;
    const loaded = page.waitForResponse("**/api/v1/firewall/rules");
    await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:staged")));
    await (await loaded).finished();
    await page.getByRole("button", { name: surface === "Firewall" ? "Save changes" : "Save filter", exact: true }).click();
    await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toBeVisible();
    await expect(input).toHaveValue(raw);
    expect(state.writes[0].revision).toBe("0123456789abcdef.1");
    await page.getByRole("button", { name: "Keep my edits", exact: true }).click();
    expect(state.writes).toHaveLength(1);
    await page.getByRole("button", { name: surface === "Firewall" ? "Save changes" : "Save filter", exact: true }).click();
    await expect.poll(() => state.writes.length).toBe(2);
    expect(state.writes[1].revision).toBe("0123456789abcdef.2");
  });
}

for (const surface of ["interfaces", "identities"]) {
  test(`${surface} creation keeps its own base while a clean row list refreshes`, async ({ page }) => {
    const state = await setup(page);
    await page.goto(`/${surface}/`);
    const input = surface === "interfaces" ? page.getByPlaceholder("name (e.g. tunnel1)") : page.getByLabel("Address", { exact: true });
    const value = surface === "interfaces" ? "new-interface" : "192.0.2.10";
    await input.fill(value);
    if (surface === "identities") await page.getByLabel("Identities", { exact: true }).fill("operator");
    state.counter++;
    const response = page.waitForResponse(`**/api/v1/${surface}`);
    await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:staged")));
    await (await response).finished();
    const save = page.getByRole("button", { name: surface === "interfaces" ? "Create" : "Bind", exact: true });
    await save.click();
    await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toBeVisible();
    await expect(input).toHaveValue(value);
    expect(state.writes[0].revision).toBe("0123456789abcdef.1");
    await page.getByRole("button", { name: "Keep my edits", exact: true }).click();
    expect(state.writes).toHaveLength(1);
    await save.click();
    await expect.poll(() => state.writes.length).toBe(2);
    expect(state.writes[1].revision).toBe("0123456789abcdef.2");
  });
}

test("delete conflict consent updates the row base used by the next deliberate delete", async ({ page }) => {
  const state = await setup(page);
  await page.goto("/zones/");
  const row = page.getByRole("row").filter({ has: page.getByRole("cell", { name: "one", exact: true }) });
  await expect(row).toBeVisible();
  state.counter++;
  const remove = async () => {
    await row.getByRole("button", { name: "Delete", exact: true }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Delete", exact: true }).click();
  };
  await remove();
  await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Keep my edits", exact: true }).click();
  expect(state.writes).toHaveLength(1);
  await remove();
  await expect.poll(() => state.writes.length).toBe(2);
  expect(state.writes.map(w => w.revision)).toEqual(["0123456789abcdef.1", "0123456789abcdef.2"]);
});

test("direct DPI changes expose conflict actions and never retry on Keep", async ({ page }) => {
  const state = await setup(page);
  await page.goto("/firewall/");
  const toggle = page.getByRole("button", { name: "Toggle DPI", exact: true });
  await expect(toggle).toBeEnabled();
  state.counter++;
  await toggle.click();
  await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Keep my edits", exact: true }).click();
  expect(state.writes).toHaveLength(1);
  await toggle.click();
  await expect.poll(() => state.writes.length).toBe(2);
  expect(state.writes[1].revision).toBe("0123456789abcdef.2");
});

test("a reverse proxy site cannot inherit a refreshed destination revision silently", async ({ page }) => {
  const state = await setup(page);
  await page.goto("/proxies/");
  await page.getByPlaceholder("site name").fill("operator-console");
  await page.getByPlaceholder("backends host:port, host:port").fill("192.0.2.10:80");
  state.counter++;
  const response = page.waitForResponse("**/api/v1/services/proxy/reverse");
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:staged")));
  await (await response).finished();
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toBeVisible();
  expect(state.writes).toHaveLength(0);
  await page.getByRole("button", { name: "Keep my edits", exact: true }).click();
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await page.getByRole("button", { name: "Save", exact: true }).last().click();
  await expect.poll(() => state.writes.length).toBe(1);
  expect(state.writes[0].revision).toBe("0123456789abcdef.2");
  expect(state.writes[0].body.sites[0].name).toBe("operator-console");
});

test("unfinished DPI exclusion input requires review before joining a refreshed list", async ({ page }) => {
  const state = await setup(page);
  await page.goto("/firewall/");
  await page.getByRole("button", { name: "Add Exclusion", exact: true }).click();
  const input = page.getByPlaceholder("192.168.1.1");
  await input.fill("192.0.2.10");
  state.counter++;
  const response = page.waitForResponse("**/api/v1/dataplane");
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:staged")));
  await (await response).finished();
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toBeVisible();
  await expect(input).toHaveValue("192.0.2.10");
  expect(state.writes).toHaveLength(0);
  await page.getByRole("button", { name: "Keep my edits", exact: true }).click();
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => state.writes.length).toBe(1);
  expect(state.writes[0].revision).toBe("0123456789abcdef.2");
});

for (const surface of ["syslog", "IDS group"]) {
  test(`${surface} unfinished local form cannot borrow a refreshed collection base`, async ({ page }) => {
    const state = await setup(page);
    const ids = surface === "IDS group";
    const endpoint = ids ? "/ids/rules" : "/services/syslog";
    await page.goto(ids ? "/ids/" : "/system/services/syslog/");
    if (ids) await page.getByRole("button", { name: /^Groups/ }).click();
    const input = page.getByPlaceholder(ids ? "e.g. ICS/Modbus" : "address", { exact: true });
    const value = ids ? "operator-group" : "192.0.2.10";
    await input.fill(value);
    state.counter++;
    const response = page.waitForResponse(`**/api/v1${endpoint}`);
    await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:staged")));
    await (await response).finished();
    await page.getByRole("button", { name: ids ? "Create" : "Add", exact: true }).click();
    await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toBeVisible();
    await expect(input).toHaveValue(value);
    expect(state.writes).toHaveLength(0);
    await page.getByRole("button", { name: "Keep my edits", exact: true }).click();
    await page.getByRole("button", { name: ids ? "Create" : "Add", exact: true }).click();
    await page.getByRole("button", { name: "Save", exact: true }).first().click();
    await expect.poll(() => state.writes.length).toBe(1);
    expect(state.writes[0].revision).toBe("0123456789abcdef.2");
  });
}

test("a clean collection continues refreshing after Keep and clears the warning after a write", async ({ page }) => {
  const state = await setup(page);
  await page.goto("/zones/");
  const row = page.getByRole("row").filter({ has: page.getByRole("cell", { name: "one", exact: true }) });
  await expect(row).toBeVisible();
  state.counter++;
  await row.getByRole("button", { name: "Delete", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Delete", exact: true }).click();
  await page.getByRole("button", { name: "Keep my edits", exact: true }).click();
  state.zones.push({ name: "three", alias: "" });
  const refreshed = page.waitForResponse("**/api/v1/zones");
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:staged")));
  await (await refreshed).finished();
  await expect(page.getByRole("cell", { name: "three", exact: true })).toBeVisible();
  await row.getByRole("button", { name: "Delete", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Delete", exact: true }).click();
  await expect.poll(() => state.counter).toBe(3);
  await expect(page.getByText("Based on an older view — review, then save again.", { exact: true })).toHaveCount(0);
  const two = page.getByRole("row").filter({ has: page.getByRole("cell", { name: "two", exact: true }) });
  await two.getByRole("button", { name: "Delete", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Delete", exact: true }).click();
  await expect.poll(() => state.counter).toBe(4);
  expect(state.writes.map(w => w.revision)).toEqual(["0123456789abcdef.1", "0123456789abcdef.2", "0123456789abcdef.3"]);
});
