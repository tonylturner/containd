import { expect, test, type Page } from "@playwright/test";

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };
const contractor = {
  id: "contractor-ssh", action: "ALLOW", sourceZones: ["it"], destZones: ["ot"],
  protocols: [{ name: "tcp", port: "22" }], identities: ["contractor"],
};
const blockSSH = { id: "block-ssh", action: "RESET", protocols: [{ name: "tcp", port: "22" }] };
const unbound = {
  ruleId: "contractor-ssh", predicate: "identity", action: "ALLOW",
  message: "no bound address can match identities [contractor]; the rule matches nothing until one is bound",
};
const shadowed = {
  ruleId: "block-ssh", shadowedBy: "allow-all-ssh", action: "RESET",
  message: "shadowed by ALLOW rule allow-all-ssh, which matches all of its traffic; a matching ALLOW takes precedence over every DENY and RESET",
};

async function openFirewall(page: Page, previews: unknown[], installed: unknown = { installed: true, appliedAt: "2026-10-26T06:00:00Z" }) {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/firewall/rules") body = [contractor, blockSSH];
    if (path === "/api/v1/zones") body = [];
    if (path === "/api/v1/routing") body = { gateways: [], routes: [], rules: [] };
    if (path === "/api/v1/dataplane") body = { captureInterfaces: [], dpiMock: false };
    if (path === "/api/v1/dataplane/ruleset") {
      body = { ruleset: "table inet containd {}", runtime: { iec104EnvelopeOpen: false, reason: "no IEC 104 rules" }, warnings: [unbound, shadowed] };
    }
    if (path === "/api/v1/dataplane/ruleset/status") body = installed;
    if (path === "/api/v1/firewall/rules/preview") {
      previews.push(request.postDataJSON());
      body = { match_count: 0, sample_matches: [], time_range: null, total_events: 12, warnings: [unbound] };
    }
    await route.fulfill({ json: body });
  });
  const loaded = Promise.all([
    page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/firewall/rules"),
    page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/dataplane/ruleset/status"),
  ]);
  await page.goto("/firewall/");
  await loaded;
}

test("rule impact preview explains an identity rule that matches nothing", async ({ page }) => {
  const previews: unknown[] = [];
  await openFirewall(page, previews);
  await page.getByRole("row").filter({ hasText: "contractor-ssh" }).getByRole("button", { name: "Edit", exact: true }).click();
  await page.getByRole("button", { name: "Preview impact" }).click();
  const summary = page.getByLabel("Rule impact preview");
  await expect(summary).toContainText("0 of 12 recent events match this rule on its own.");
  const warning = summary.getByRole("status");
  await expect(warning).toContainText("Rules that do not act as written");
  await expect(warning).toContainText(`unbound identity`);
  await expect(warning).toContainText(`contractor-ssh: ${unbound.message}`);
  expect(previews).toHaveLength(1);
  expect(previews[0]).toMatchObject({ id: "contractor-ssh", action: "ALLOW", identities: ["contractor"] });
});

test("ruleset preview lists unbound identities and shadowed rules", async ({ page }) => {
  await openFirewall(page, []);
  await page.getByRole("button", { name: "Preview", exact: true }).click();
  const list = page.getByRole("status", { name: "Candidate rule warnings" });
  await expect(list).toContainText("staged, not yet applied");
  const items = list.getByRole("listitem");
  await expect(items).toHaveCount(2);
  await expect(items.nth(0)).toContainText("unbound identity");
  await expect(items.nth(0)).toContainText(`contractor-ssh: ${unbound.message}`);
  await expect(items.nth(1)).toContainText("shadowed");
  await expect(items.nth(1)).toContainText(`block-ssh: ${shadowed.message}`);
  await expect(page.getByText("resolved toward denial")).toHaveCount(0);
});

test("applied warnings are listed apart from the candidate's", async ({ page }) => {
  await openFirewall(page, [], { installed: true, appliedAt: "2026-10-26T06:00:00Z", warnings: [shadowed] });
  const applied = page.getByRole("status", { name: "Applied rule warnings" });
  await expect(applied.getByRole("listitem")).toHaveCount(1);
  await page.getByRole("button", { name: "Preview", exact: true }).click();
  const candidate = page.getByRole("status", { name: "Candidate rule warnings" });
  await expect(candidate.getByRole("listitem")).toHaveCount(2);
  await expect(applied).toContainText("the running ruleset");
  await expect(applied.getByRole("listitem")).toHaveCount(1);
  await expect(applied).toContainText(`block-ssh: ${shadowed.message}`);
  await expect(applied).not.toContainText("contractor-ssh");
});

test("no applied warnings shows no applied list", async ({ page }) => {
  await openFirewall(page, []);
  await page.getByRole("button", { name: "Preview", exact: true }).click();
  await expect(page.getByRole("status", { name: "Candidate rule warnings" })).toBeVisible();
  await expect(page.getByRole("status", { name: "Applied rule warnings" })).toHaveCount(0);
});

test("ruleset preview explains rules that match nothing because of zones or address families", async ({ page }) => {
  const zone = {
    ruleId: "dmz-in", predicate: "zone", zones: ["dmz", "lab"], action: "ALLOW",
    message: "no interface is assigned to zones dmz, lab; the rule matches nothing until one is",
  };
  const family = {
    ruleId: "v6-to-v4", predicate: "addressFamily", action: "DENY",
    message: "its sources and destinations share no address family (IPv4 or IPv6); the rule matches nothing",
  };
  await openFirewall(page, []);
  await page.route("**/api/v1/dataplane/ruleset", (route) => route.fulfill({
    json: { ruleset: "table inet containd {}", runtime: { iec104EnvelopeOpen: false, reason: "no IEC 104 rules" }, warnings: [zone, family, unbound] },
  }));
  await page.getByRole("button", { name: "Preview", exact: true }).click();
  const items = page.getByRole("status", { name: "Candidate rule warnings" }).getByRole("listitem");
  await expect(items).toHaveCount(3);
  await expect(items.nth(0)).toContainText("zone without interfaces");
  await expect(items.nth(0)).toContainText(`dmz-in: ${zone.message}`);
  await expect(items.nth(0).getByRole("link", { name: "Assign an interface" })).toHaveAttribute("href", "/interfaces/");
  await expect(items.nth(1)).toContainText("no shared address family");
  await expect(items.nth(1)).toContainText(`v6-to-v4: ${family.message}`);
  await expect(items.nth(1).getByRole("link")).toHaveCount(0);
  await expect(items.nth(2).getByRole("link", { name: "Bind an address" })).toHaveAttribute("href", "/identities/");
});
