import { expect, test, type Page } from "@playwright/test";

// Coverage, not the configured mode, decides whether the UI shows an ICS rule
// as protected. These pages read candidate and applied coverage from the
// ruleset preview and the aggregate from health; every field may be absent.

const admin = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };
const viewer = { id: "view-1", username: "operator", role: "view", mfaRequired: false };

function icsRule(id: string, protocol: string, mode?: "enforce" | "learn") {
  return {
    id,
    action: "ALLOW",
    sourceZones: ["it"],
    destZones: ["ot"],
    protocols: [{ name: "tcp", port: protocol === "dnp3" ? "20000" : "502" }],
    ics: { protocol, functionCode: [3], ...(mode ? { mode } : {}) },
  };
}

const rules = [
  icsRule("plc-read", "modbus", "enforce"),
  icsRule("plc-inherit", "modbus"),
  icsRule("dnp3-ops", "dnp3", "enforce"),
  icsRule("plc-learn", "modbus", "learn"),
  icsRule("plc-pending", "modbus", "enforce"),
  icsRule("plc-drift", "modbus", "enforce"),
  { id: "l4-only", action: "ALLOW", sourceZones: ["it"], destZones: ["ot"], protocols: [{ name: "tcp", port: "22" }] },
];

const exclusion = {
  code: "exclusion-overlap",
  message: "DPI exclusion 10.20.0.0/24 meets the rule scope; matching flows are not inspected",
  value: "10.20.0.0/24",
};
const dpiOff = { code: "dpi-disabled", message: "DPI is switched off; nothing inspects this rule's traffic" };
const queueDown = { code: "queue-unavailable", message: "NFQUEUE group 101 is not bound by this engine" };

function cov(ruleId: string, state: string, mode = "enforce", reasons?: unknown[]) {
  return { ruleId, protocol: ruleId.startsWith("dnp3") ? "dnp3" : "modbus", mode, state, ...(reasons ? { reasons } : {}) };
}

const candidate = [
  cov("plc-read", "enforcing"),
  cov("plc-inherit", "partial", "enforce", [exclusion]),
  cov("dnp3-ops", "not_enforcing", "enforce", [dpiOff]),
  cov("plc-learn", "monitoring", "learn"),
  cov("plc-pending", "enforcing"),
  cov("plc-drift", "enforcing"),
];
const applied = [
  cov("plc-read", "enforcing"),
  cov("plc-inherit", "partial", "enforce", [{ ...exclusion, matches: 7 }]),
  cov("dnp3-ops", "not_enforcing", "enforce", [dpiOff]),
  cov("plc-learn", "monitoring", "learn"),
  cov("plc-drift", "not_enforcing", "enforce", [queueDown]),
];
const ruleset = {
  ruleset: "table inet containd {}",
  runtime: { iec104EnvelopeOpen: false, reason: "no IEC 104 rules" },
  icsCoverage: candidate,
  engineStatus: { ruleset: "table inet containd {}", appliedAt: "2026-10-26T09:00:00Z", icsCoverage: applied },
};
const health = {
  status: "ok",
  component: "mgmt",
  icsEnforcement: { state: "not_enforcing", enforcing: 1, partial: 1, notEnforcing: 2, monitoring: 1 },
};

type Mocks = {
  user?: typeof admin;
  rules?: unknown[];
  dataplane?: unknown;
  ruleset?: { status: number; json: unknown };
  health?: unknown;
  preview?: unknown;
};

async function mockAPI(page: Page, mocks: Mocks): Promise<{ rulesetRequests: number; errors: string[] }> {
  const user = mocks.user ?? admin;
  const seen = { rulesetRequests: 0, errors: [] as string[] };
  page.on("pageerror", (err) => seen.errors.push(String(err)));
  await page.addInitScript((role) => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", role);
  }, user.role);
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/dataplane/ruleset") {
      seen.rulesetRequests++;
      await route.fulfill(mocks.ruleset ?? { status: 200, json: ruleset });
      return;
    }
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/firewall/rules") body = mocks.rules ?? rules;
    if (path === "/api/v1/zones") body = [];
    if (path === "/api/v1/routing") body = { gateways: [], routes: [], rules: [] };
    if (path === "/api/v1/dataplane") body = mocks.dataplane ?? { dpiEnabled: true, dpiMode: "enforce", nfqueueGroup: 101 };
    if (path === "/api/v1/health") body = mocks.health ?? health;
    if (path === "/api/v1/firewall/rules/preview") body = mocks.preview ?? {};
    await route.fulfill({ json: body });
  });
  return seen;
}

async function open(page: Page, path: string, admin = true) {
  const loaded = [page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/firewall/rules")];
  if (admin) loaded.push(page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/dataplane/ruleset"));
  await page.goto(path);
  await Promise.all(loaded);
}

function coverageOf(page: Page, ruleId: string) {
  return page.getByLabel(`ICS coverage of ${ruleId}`);
}

test("ICS page shows applied coverage for each state, never mode alone", async ({ page }) => {
  const seen = await mockAPI(page, {});
  await open(page, "/ics/");

  const read = coverageOf(page, "plc-read");
  await expect(read.getByText("applied: enforcing")).toHaveClass(/badge-secure/);
  await expect(read.getByRole("status")).toHaveCount(1);

  const inherit = coverageOf(page, "plc-inherit");
  await expect(inherit.getByText("applied: partial")).toHaveClass(/badge-warning/);
  await expect(inherit).toContainText("DPI exclusion 10.20.0.0/24 meets the rule scope; matching flows are not inspected — 7 flows bypassed inspection since apply");
  // Runtime matches alone do not show a differing candidate.
  await expect(inherit.getByText(/^candidate:/)).toHaveCount(0);

  const dnp3 = coverageOf(page, "dnp3-ops");
  await expect(dnp3.getByText("applied: not enforcing")).toHaveClass(/badge-critical/);
  await expect(dnp3).toContainText(dpiOff.message);

  await expect(coverageOf(page, "plc-learn").getByText("applied: monitoring")).toHaveClass(/badge-offline/);

  const pending = coverageOf(page, "plc-pending");
  await expect(pending.getByText("not applied")).toHaveClass(/badge-offline/);
  await expect(pending.getByText("candidate: enforcing")).toBeVisible();

  const drift = coverageOf(page, "plc-drift");
  await expect(drift.getByText("applied: not enforcing")).toHaveClass(/badge-critical/);
  await expect(drift).toContainText(queueDown.message);
  await expect(drift.getByText("candidate: enforcing")).toBeVisible();

  // The mode column states the effective mode with no protection colour.
  const inheritRow = page.getByRole("row").filter({ hasText: "plc-inherit" });
  await expect(inheritRow.getByText("inherit (enforce)")).toHaveClass(/badge-offline/);
  await expect(page.getByRole("row").filter({ hasText: "plc-learn" }).getByText("learning", { exact: true })).toHaveClass(/badge-offline/);

  // Green appears only on enforcing coverage (the DPI switch badge sits outside the table).
  await expect(page.locator("table .badge-secure")).toHaveText([
    "applied: enforcing",
    "candidate: enforcing",
    "candidate: enforcing",
  ]);
  expect(seen.errors).toEqual([]);
});

test("ICS page shows the runtime aggregate and the NFQUEUE inline path", async ({ page }) => {
  await mockAPI(page, {});
  await open(page, "/ics/");

  await expect(page.getByRole("status", { name: /ICS protocol rules not enforcing/ })).toBeVisible();
  await expect(page.getByText("1 enforcing, 1 partial, 2 not enforcing, 1 monitoring")).toBeVisible();
  await expect(page.getByText("Inline inspection: NFQUEUE group 101")).toBeVisible();
  await expect(page.getByText("needs no capture interface", { exact: false })).toBeVisible();
  await expect(page.getByText("at least one capture interface")).toHaveCount(0);
});

test("ICS page without an inline path says rules can only monitor", async ({ page }) => {
  await mockAPI(page, {
    dataplane: { dpiEnabled: true, captureInterfaces: ["lan1"] },
    health: { status: "ok", component: "mgmt", icsEnforcement: { state: "monitoring", monitoring: 6 } },
  });
  await open(page, "/ics/");
  await expect(page.getByText("Inline inspection: off — no NFQUEUE group, so ICS rules can only monitor")).toBeVisible();
  await expect(page.getByRole("status", { name: /ICS protocol rules monitoring only/ })).toBeVisible();
});

test("responses without coverage fields render no protection and no crash", async ({ page }) => {
  const seen = await mockAPI(page, {
    ruleset: { status: 200, json: { ruleset: "table inet containd {}", engineStatus: { ruleset: "x" } } },
    health: { status: "ok", component: "mgmt" },
  });
  await open(page, "/ics/");

  await expect(coverageOf(page, "plc-read").getByText("not applied")).toBeVisible();
  await expect(coverageOf(page, "plc-read").getByText(/^candidate:/)).toHaveCount(0);
  await expect(page.locator("table .badge-secure")).toHaveCount(0);
  await expect(page.getByRole("status", { name: /ICS protocol enforcement/ })).toContainText("status unavailable");
  expect(seen.errors).toEqual([]);
});

test("missing engine status keeps candidate coverage and says applied is unknown", async ({ page }) => {
  const seen = await mockAPI(page, {
    ruleset: {
      status: 200,
      json: { icsCoverage: [cov("plc-read", "partial", "enforce", [exclusion])], engineStatusError: "engine unreachable" },
    },
  });
  await open(page, "/ics/");

  await expect(page.getByText("Applied ICS coverage unavailable: engine unreachable.")).toBeVisible();
  const read = coverageOf(page, "plc-read");
  await expect(read.getByText("applied: unknown")).toHaveClass(/badge-offline/);
  await expect(read.getByText("candidate: partial")).toHaveClass(/badge-warning/);
  await expect(coverageOf(page, "plc-inherit").getByText("applied: unknown")).toBeVisible();
  expect(seen.errors).toEqual([]);
});

test("an engine apply error is reported beside the applied coverage", async ({ page }) => {
  await mockAPI(page, {
    ruleset: { status: 200, json: { ...ruleset, engineStatus: { ...ruleset.engineStatus, error: "nft: syntax error" } } },
  });
  await open(page, "/ics/");
  await expect(page.getByText("The engine reported an apply error: nft: syntax error")).toBeVisible();
});

test("an unavailable ruleset preview reports why and claims no coverage", async ({ page }) => {
  const seen = await mockAPI(page, {
    ruleset: { status: 400, json: { error: "rule plc-read: ics enforce requires dataplane.nfqueueGroup" } },
  });
  await open(page, "/ics/");

  await expect(page.getByText("ICS coverage unavailable: rule plc-read: ics enforce requires dataplane.nfqueueGroup.", { exact: false })).toBeVisible();
  await expect(coverageOf(page, "plc-read").getByText("coverage unavailable")).toHaveClass(/badge-offline/);
  await expect(page.locator("table .badge-secure")).toHaveCount(0);
  expect(seen.errors).toEqual([]);
});

test("a viewer sees the runtime aggregate and no per-rule claim", async ({ page }) => {
  const seen = await mockAPI(page, { user: viewer });
  await open(page, "/ics/", false);

  await expect(page.getByText("Per-rule ICS coverage requires admin access.", { exact: false })).toBeVisible();
  await expect(coverageOf(page, "plc-read").getByText("coverage: admin only")).toBeVisible();
  await expect(page.getByRole("status", { name: /ICS protocol rules not enforcing/ })).toBeVisible();
  await expect(page.locator("table .badge-secure")).toHaveCount(0);
  expect(seen.rulesetRequests).toBe(0);
  expect(seen.errors).toEqual([]);
});

test("firewall table labels an inherited mode by its effective mode", async ({ page }) => {
  await mockAPI(page, { dataplane: { dpiEnabled: true } });
  await open(page, "/firewall/");

  const inheritRow = page.getByRole("row").filter({ hasText: "plc-inherit" });
  await expect(inheritRow.getByText("inherit (learning)")).toHaveClass(/badge-offline/);
  await expect(inheritRow.getByText("enforce", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("row").filter({ hasText: "plc-read" }).getByText("enforce", { exact: true })).toBeVisible();
  await expect(page.getByRole("row").filter({ hasText: "plc-learn" }).getByText("learning", { exact: true })).toBeVisible();
});

test("firewall table shows coverage beside the effective mode", async ({ page }) => {
  const seen = await mockAPI(page, {});
  await open(page, "/firewall/");

  const inheritRow = page.getByRole("row").filter({ hasText: "plc-inherit" });
  await expect(inheritRow.getByText("inherit (enforce)")).toBeVisible();
  await expect(coverageOf(page, "plc-inherit").getByText("applied: partial")).toHaveClass(/badge-warning/);
  await expect(coverageOf(page, "dnp3-ops").getByText("applied: not enforcing")).toHaveClass(/badge-critical/);
  await expect(coverageOf(page, "plc-drift").getByText("candidate: enforcing")).toBeVisible();
  await expect(coverageOf(page, "l4-only")).toHaveCount(0);
  expect(seen.errors).toEqual([]);
});

test("firewall without ICS protocol rules shows no coverage notice", async ({ page }) => {
  await mockAPI(page, { user: viewer, rules: [rules[6]] });
  await open(page, "/firewall/", false);
  await expect(page.getByRole("row").filter({ hasText: "l4-only" })).toBeVisible();
  await expect(page.getByText("Per-rule ICS coverage requires admin access.", { exact: false })).toHaveCount(0);
});

test("rule preview shows coverage in its own section, apart from denial warnings", async ({ page }) => {
  const warning = {
    ruleId: "plc-read",
    predicate: "schedule",
    action: "ALLOW",
    message: "schedules are enforced only on ICS rules inspected through NFQUEUE; ALLOW rule inactive",
  };
  await mockAPI(page, {
    rules: [rules[0]],
    preview: {
      match_count: 3,
      sample_matches: [],
      time_range: null,
      total_events: 9,
      warnings: [warning],
      icsCoverage: cov("plc-read", "not_enforcing", "enforce", [dpiOff]),
    },
  });
  await open(page, "/ics/");
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  await page.getByRole("button", { name: "Preview impact" }).click();

  const summary = page.getByLabel("Rule impact preview");
  const section = summary.getByLabel("ICS coverage", { exact: true });
  await expect(section.getByText("not enforcing", { exact: true })).toHaveClass(/badge-critical/);
  await expect(section).toContainText("effective mode: enforce");
  await expect(section).toContainText(dpiOff.message);
  const denial = summary.getByRole("status").filter({ hasText: "Rule predicates resolved toward denial" });
  await expect(denial).toContainText(warning.message);
  await expect(denial).not.toContainText(dpiOff.message);
});

test("rule preview without coverage shows no coverage section", async ({ page }) => {
  const seen = await mockAPI(page, {
    rules: [rules[0]],
    preview: { match_count: 0, sample_matches: [], time_range: null, total_events: 0 },
  });
  await open(page, "/firewall/");
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  await page.getByRole("button", { name: "Preview impact" }).click();
  const summary = page.getByLabel("Rule impact preview");
  await expect(summary).toContainText("0 of 0 recent events match this rule on its own.");
  await expect(summary.getByLabel("ICS coverage", { exact: true })).toHaveCount(0);
  expect(seen.errors).toEqual([]);
});
