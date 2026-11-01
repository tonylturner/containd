import { expect, test, type Page } from "@playwright/test";
import type { FirewallRule, Position } from "../lib/api";

async function openFirewall(page: Page, hash = "") {
  let rules: FirewallRule[] = [
    { id: "deny-all", action: "DENY" },
    { id: "allow-ssh", action: "ALLOW", protocols: [{ name: "tcp", port: "22" }], viaForwards: ["ssh"] },
    { id: "allow-web", action: "ALLOW" },
  ];
  const moves: { id: string; position: Position }[] = [];
  const creates: unknown[] = [];
  const patches: unknown[] = [];
  let rejectMove = false;
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    let json: unknown = {};
    if (path.endsWith("/auth/me") || path.endsWith("/auth/session")) json = { id: "admin", role: "admin" };
    if (path.endsWith("/config/diff")) json = { changed: false, changedSections: [] };
    if (path === "/api/v1/zones") json = [{ name: "wan" }];
    if (path === "/api/v1/routing") json = { routes: [], rules: [], gateways: [] };
    if (path === "/api/v1/dataplane") json = { captureInterfaces: [], dpiMock: false };
    if (path === "/api/v1/firewall/nat") json = { enabled: true, portForwards: [
      { id: "ssh", enabled: true, ingressZone: "wan", proto: "tcp", listenPort: 2222, destIp: "192.0.2.5", destPort: 22 },
      { id: "web", enabled: true, ingressZone: "wan", proto: "tcp", listenPort: 8443, destIp: "192.0.2.6", destPort: 443 },
    ] };
    if (path === "/api/v1/firewall/rules") {
      if (request.method() === "POST") {
        const body = request.postDataJSON();
        creates.push(body);
        json = { ...body, index: 0 };
      } else json = rules;
    }
    if (path.endsWith("/move")) {
      const { position } = request.postDataJSON() as { position: Position };
      const id = decodeURIComponent(path.split("/").at(-2)!);
      moves.push({ id, position });
      if (rejectMove) return route.fulfill({ status: 400, json: { error: "Unknown anchor" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
      const moved = rules.find((r) => r.id === id)!;
      rules = rules.filter((r) => r.id !== id);
      const index = position === "top" ? 0 : position === "bottom" ? rules.length
        : "before" in position ? rules.findIndex((r) => r.id === position.before)
          : rules.findIndex((r) => r.id === position.after) + 1;
      rules.splice(index, 0, moved);
      json = { index, rules };
    }
    if (request.method() === "PATCH") {
      const patch = request.postDataJSON();
      patches.push(patch);
      const id = path.split("/").at(-1);
      json = { ...rules.find((r) => r.id === id), ...patch };
    }
    if (path === "/api/v1/dataplane/ruleset") json = { ruleset: "table inet containd {}", warnings: [{
      ruleId: "allow-ssh", action: "ALLOW", shadowedBy: "deny-all",
      message: "rule at position 2 is shadowed by earlier DENY rule deny-all at position 1",
    }] };
    await route.fulfill({ json, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/firewall/rules");
  await page.goto(`/firewall/${hash}`);
  await loaded;
  return { moves, creates, patches, reject: () => { rejectMove = true; }, remove: (id: string) => { rules = rules.filter((r) => r.id !== id); } };
}

function ruleRow(page: Page, id: string) {
  return page.getByRole("row").filter({ has: page.getByRole("cell", { name: id, exact: true }) });
}

async function expectOrder(page: Page, ids: string[]) {
  const rows = page.getByRole("region", { name: "Firewall rules" }).locator("tbody tr");
  await expect(rows.locator("td:nth-child(2)")).toHaveText(ids);
  await expect(rows.locator("td:first-child")).toHaveText(ids.map((_, i) => String(i + 1)));
}

test("move up and down persist through the move endpoint and refresh", async ({ page }) => {
  const server = await openFirewall(page);
  await expectOrder(page, ["deny-all", "allow-ssh", "allow-web"]);
  await expect(page.getByLabel("Move deny-all up")).toBeDisabled();
  await expect(page.getByLabel("Move allow-web down")).toBeDisabled();
  await page.getByLabel("Move allow-ssh up").click();
  await expectOrder(page, ["allow-ssh", "deny-all", "allow-web"]);
  await expect(page.getByText("Rule moved to position 1", { exact: false })).toBeVisible();
  await page.getByLabel("Move allow-ssh down").click();
  await expectOrder(page, ["deny-all", "allow-ssh", "allow-web"]);
  expect(server.moves).toEqual([
    { id: "allow-ssh", position: { before: "deny-all" } },
    { id: "allow-ssh", position: { after: "deny-all" } },
  ]);
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expectOrder(page, ["deny-all", "allow-ssh", "allow-web"]);
});

test("forward rule links scroll to their asynchronously loaded row", async ({ page }) => {
  await openFirewall(page, "#rule-allow-ssh");
  await expect(ruleRow(page, "allow-ssh")).toBeInViewport();
});

test("a create placement keeps its chosen anchor visibly when a background refresh removes it", async ({ page }) => {
  const server = await openFirewall(page);
  const position = page.getByLabel("Position", { exact: true });
  await position.selectOption(JSON.stringify({ before: "deny-all" }));
  server.remove("deny-all");
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/firewall/rules");
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:staged")));
  await loaded;
  await expect(position).toHaveValue(JSON.stringify({ before: "deny-all" }));
  await expect(position.getByRole("option", { name: "Before deny-all (no longer on server)", exact: true })).toHaveCount(1);
});

test("Move to supports top, bottom, before and after without moving on failure", async ({ page }) => {
  const server = await openFirewall(page);
  const move = async (position: Position, expected: string[]) => {
    await ruleRow(page, "allow-web").getByRole("button", { name: "Move to…" }).click();
    const dialog = page.getByRole("dialog", { name: "Move rule allow-web" });
    await expect(dialog.getByRole("option", { name: "Before allow-web", exact: true })).toHaveCount(0);
    await dialog.getByLabel("Position").selectOption(JSON.stringify(position));
    await dialog.getByRole("button", { name: "Move", exact: true }).click();
    await expectOrder(page, expected);
  };
  await move("top", ["allow-web", "deny-all", "allow-ssh"]);
  await move("bottom", ["deny-all", "allow-ssh", "allow-web"]);
  await move({ before: "allow-ssh" }, ["deny-all", "allow-web", "allow-ssh"]);
  await move({ after: "allow-ssh" }, ["deny-all", "allow-ssh", "allow-web"]);
  server.reject();
  await move("top", ["deny-all", "allow-ssh", "allow-web"]);
  await expect(page.getByText("Unknown anchor", { exact: true })).toBeVisible();
  expect(server.moves.map((m) => m.position)).toEqual(["top", "bottom", { before: "allow-ssh" }, { after: "allow-ssh" }, "top"]);
});

test("a later ALLOW covered by an earlier DENY shows the server's shadow warning", async ({ page }) => {
  await openFirewall(page);
  await page.getByRole("button", { name: "Preview", exact: true }).click();
  const warning = page.getByRole("status", { name: "Candidate rule warnings" });
  await expect(warning).toContainText("allow-ssh");
  await expect(warning).toContainText("earlier DENY rule deny-all at position 1");
});

test("create chooses placement and via forwards; edit can clear every via restriction", async ({ page }) => {
  const server = await openFirewall(page);
  const form = page.locator("section").filter({ has: page.getByRole("heading", { name: "Create rule", exact: true }) });
  await expect(form.getByLabel("Position", { exact: true })).toHaveValue('"bottom"');
  await form.getByPlaceholder("id (e.g. mb-allow)").fill("new-rule");
  await form.getByLabel("Position", { exact: true }).selectOption(JSON.stringify({ before: "deny-all" }));
  await form.getByLabel(/web: wan tcp ingress-local:8443 → 192.0.2.6:443/).check();
  await form.getByLabel(/ssh: wan tcp/).check();
  await form.getByRole("button", { name: "Create rule", exact: true }).click();
  await expect.poll(() => server.creates.length).toBe(1);
  expect(server.creates[0]).toMatchObject({ position: { before: "deny-all" }, viaForwards: ["web", "ssh"] });
  await ruleRow(page, "allow-ssh").getByRole("button", { name: "Edit", exact: true }).click();
  const editor = page.locator("div.fixed").filter({ has: page.getByRole("heading", { name: "Edit rule allow-ssh" }) });
  await expect(editor.getByLabel(/ssh: wan tcp/)).toBeChecked();
  await editor.getByLabel(/ssh: wan tcp/).uncheck();
  await editor.getByRole("button", { name: "Save changes" }).click();
  await expect.poll(() => server.patches.length).toBe(1);
  expect(server.patches[0]).toMatchObject({ viaForwards: [] });
});

test("Move to is keyboard accessible and Escape cancels without staging", async ({ page }) => {
  const server = await openFirewall(page);
  const trigger = ruleRow(page, "allow-ssh").getByRole("button", { name: "Move to…" });
  await trigger.click();
  const dialog = page.getByRole("dialog", { name: "Move rule allow-ssh" });
  await expect(dialog.getByLabel("Position", { exact: true })).toBeFocused();
  await page.keyboard.press("Shift+Tab");
  await expect(dialog.getByRole("button", { name: "Move", exact: true })).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(dialog.getByLabel("Position", { exact: true })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(trigger).toBeFocused();
  expect(server.moves).toEqual([]);
});
