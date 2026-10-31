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
  message: "rule at position 2 is shadowed by earlier ALLOW rule allow-all-ssh at position 1, which matches all of its traffic",
};

const range = { start: "2026-10-26T08:00:00Z", end: "2026-10-26T09:15:02Z" };
const noMatch = { match_count: 0, sample_matches: [], time_range: range, total_events: 12, warnings: [unbound] };

async function openFirewall(
  page: Page,
  previews: unknown[],
  installed: unknown = { installed: true, appliedAt: "2026-10-26T06:00:00Z" },
  preview: unknown = noMatch,
  candidate: unknown = contractor,
) {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/firewall/rules") body = [candidate, blockSSH];
    if (path === "/api/v1/zones") body = [];
    if (path === "/api/v1/routing") body = { gateways: [], routes: [], rules: [] };
    if (path === "/api/v1/dataplane") body = { captureInterfaces: [], dpiMock: false };
    if (path === "/api/v1/dataplane/ruleset") {
      body = { ruleset: "table inet containd {}", runtime: { iec104EnvelopeOpen: false, reason: "no IEC 104 rules" }, warnings: [unbound, shadowed] };
    }
    if (path === "/api/v1/dataplane/ruleset/status") body = installed;
    if (path === "/api/v1/firewall/rules/preview") {
      previews.push(request.postDataJSON());
      body = preview;
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
  await expect(summary.locator(`time[datetime="${range.start}"]`)).toBeVisible();
  await expect(summary.locator(`time[datetime="${range.end}"]`)).toBeVisible();
  await expect(summary.getByText(/sample event/)).toHaveCount(0);
  const warning = summary.getByRole("status");
  await expect(warning).toContainText("Rules that do not act as written");
  await expect(warning).toContainText(`unbound identity`);
  await expect(warning).toContainText(`contractor-ssh: ${unbound.message}`);
  expect(previews).toHaveLength(1);
  expect(previews[0]).toMatchObject({ id: "contractor-ssh", action: "ALLOW", identities: ["contractor"] });
});

async function previewContractor(page: Page, preview: unknown) {
  await openFirewall(page, [], undefined, preview);
  await page.getByRole("row").filter({ hasText: "contractor-ssh" }).getByRole("button", { name: "Edit", exact: true }).click();
  await page.getByRole("button", { name: "Preview impact" }).click();
  return page.getByLabel("Rule impact preview");
}

test("rule impact preview lists the time range and collapsed sample events", async ({ page }) => {
  const modbus = {
    id: "41", flowId: "flow-1", proto: "modbus", kind: "request", timestamp: "2026-10-26T09:15:02Z",
    attributes: { function_code: 3, unit_id: 1 },
    srcIp: "10.10.0.5", dstIp: "10.20.0.7", srcPort: 40100, dstPort: 502, transport: "tcp",
  };
  const iec = {
    id: "40", flowId: "flow-2", proto: "iec104", kind: "request", timestamp: "2026-10-26T09:10:00Z",
    attributes: { type_id: 45, direction: "request" },
    srcIp: "2001:db8::5", dstIp: "2001:db8::7", srcPort: 40200, dstPort: 2404, transport: "tcp",
  };
  const ping = {
    id: "39", flowId: "flow-3", proto: "firewall", kind: "flow.allow", timestamp: "2026-10-26T08:00:00Z",
    srcIp: "10.10.0.6", dstIp: "10.20.0.8", transport: "icmp",
  };
  const summary = await previewContractor(page, {
    match_count: 1234, sample_matches: [modbus, iec, ping], time_range: range, total_events: 5000,
  });
  await expect(summary).toContainText("1234 of 5000 recent events match this rule on its own.");
  const searched = summary.locator("p", { hasText: "Events searched:" });
  await expect(searched.locator(`time[datetime="${range.start}"]`)).toBeVisible();
  await expect(searched.locator(`time[datetime="${range.end}"]`)).toBeVisible();

  const samples = summary.getByRole("list", { name: "Sample matching events" });
  const toggle = summary.getByText("Show 3 sample events");
  await expect(toggle).toContainText("(the newest of 1234 matches)");
  await expect(samples).toBeHidden();
  await toggle.click();
  await expect(summary.getByText("Hide 3 sample events")).toBeVisible();
  const rows = samples.getByRole("listitem");
  await expect(rows).toHaveCount(3);
  await expect(rows.nth(0)).toContainText("modbus / request");
  await expect(rows.nth(0)).toContainText("function 3");
  await expect(rows.nth(0)).toContainText("10.10.0.5:40100 → 10.20.0.7:502 (tcp)");
  await expect(rows.nth(0).locator(`time[datetime="${modbus.timestamp}"]`)).toBeVisible();
  await expect(rows.nth(1)).toContainText("type 45 C_SC_NA_1 single command");
  await expect(rows.nth(1)).toContainText("[2001:db8::5]:40200 → [2001:db8::7]:2404 (tcp)");
  await expect(rows.nth(2)).toContainText("firewall / flow.allow");
  await expect(rows.nth(2)).toContainText("10.10.0.6 → 10.20.0.8 (icmp)");
  await expect(rows.nth(2)).not.toContainText(/function|service|type/);
});

test("rule impact preview says when there were no events to search", async ({ page }) => {
  const summary = await previewContractor(page, { match_count: 0, sample_matches: [], time_range: null, total_events: 0 });
  await expect(summary).toContainText("No recent events to search: the engine has retained none yet.");
  await expect(summary).not.toContainText("of 0 recent events");
  await expect(summary).not.toContainText("Events searched");
  await expect(summary.getByText(/sample event/)).toHaveCount(0);
});

test("a via rule explains unavailable historical counting while retaining warnings and ICS coverage", async ({ page }) => {
  const unavailable = "Retained events do not record which connections containd translated, so a rule limited to port forwards cannot be previewed from history.";
  const warning = {
    ruleId: contractor.id, predicate: "forward", action: "ALLOW",
    message: "Referenced port forward modbus-pf is disabled.",
  };
  const previews: unknown[] = [];
  await openFirewall(page, previews, undefined, {
    unavailable, match_count: 0, sample_matches: [], time_range: range, total_events: 12,
    warnings: [warning],
    icsCoverage: {
      ruleId: contractor.id, protocol: "modbus", mode: "enforce", state: "not_enforcing",
      reasons: [{ code: "no-inline-path", message: "No inline capture path available." }],
    },
  }, { ...contractor, viaForwards: ["modbus-pf"], ics: { protocol: "modbus", mode: "enforce" } });
  await page.getByRole("row").filter({ hasText: contractor.id }).getByRole("button", { name: "Edit", exact: true }).click();
  await page.getByRole("button", { name: "Preview impact" }).click();
  const summary = page.getByLabel("Rule impact preview");
  await expect(summary.getByText(unavailable, { exact: true })).toBeVisible();
  await expect(summary).not.toContainText("recent events match");
  await expect(summary).not.toContainText("No recent events to search");
  await expect(summary).not.toContainText("Events searched");
  await expect(summary.getByRole("list", { name: "Sample matching events" })).toHaveCount(0);
  await expect(summary.getByText(/sample event/)).toHaveCount(0);
  await expect(summary.getByRole("status").filter({ hasText: "Rules that do not act as written" })).toContainText(warning.message);
  const coverage = summary.getByLabel("ICS coverage", { exact: true });
  await expect(coverage).toContainText("effective mode: enforce");
  await expect(coverage).toContainText("No inline capture path available.");
  expect(previews).toHaveLength(1);
  expect(previews[0]).toMatchObject({ viaForwards: ["modbus-pf"], ics: { protocol: "modbus" } });
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
