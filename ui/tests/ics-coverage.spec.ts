import { expect, test, type Page } from "@playwright/test";

// Coverage, not the configured mode, decides whether the UI shows an ICS rule
// as protected. Pages read candidate and applied coverage from
// GET /dataplane/ics-coverage (any authenticated user) and the aggregate from
// health; every field may be absent.

const admin = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };
const viewer = { id: "view-1", username: "operator", role: "view", mfaRequired: false };

function icsRule(id: string, protocol: string, mode?: "enforce" | "monitor") {
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
  icsRule("plc-learn", "modbus", "monitor"),
  icsRule("plc-pending", "modbus", "enforce"),
  icsRule("plc-drift", "modbus", "enforce"),
  icsRule("plc-queue", "modbus", "enforce"),
  { id: "l4-only", action: "ALLOW", sourceZones: ["it"], destZones: ["ot"], protocols: [{ name: "tcp", port: "22" }] },
];

const exclusion = {
  code: "exclusion-overlap",
  message: "DPI exclusion 10.20.0.0/24 meets the rule scope; matching flows are not inspected",
  value: "10.20.0.0/24",
};
const dpiOff = { code: "dpi-disabled", message: "DPI is switched off; nothing inspects this rule's traffic" };
const decoderOff = { code: "decoder-disabled", message: "the modbus decoder is switched off" };
const queueDown = { code: "queue-unavailable", message: "NFQUEUE group 101 is not bound by this engine", runtime: true };

function cov(ruleId: string, state: string, mode = "enforce", reasons?: unknown[]) {
  return { ruleId, protocol: ruleId.startsWith("dnp3") ? "dnp3" : "modbus", mode, state, ...(reasons ? { reasons } : {}) };
}

const candidate = [
  cov("plc-read", "enforcing"),
  cov("plc-inherit", "partial", "enforce", [exclusion]),
  cov("dnp3-ops", "not_enforcing", "enforce", [dpiOff]),
  cov("plc-learn", "monitoring", "monitor"),
  cov("plc-pending", "enforcing"),
  cov("plc-drift", "enforcing"),
  cov("plc-queue", "enforcing"),
];
const applied = [
  cov("plc-read", "enforcing"),
  cov("plc-inherit", "partial", "enforce", [{ ...exclusion, matches: 7 }]),
  cov("dnp3-ops", "not_enforcing", "enforce", [dpiOff]),
  cov("plc-learn", "monitoring", "monitor"),
  cov("plc-drift", "not_enforcing", "enforce", [decoderOff]),
  cov("plc-queue", "not_enforcing", "enforce", [queueDown]),
];
const report = { candidate, applied, appliedAt: "2026-10-26T09:00:00Z" };
const health = {
  status: "ok",
  component: "mgmt",
  icsEnforcement: { state: "not_enforcing", enforcing: 1, partial: 1, notEnforcing: 3, monitoring: 1 },
};

type Mocks = {
  user?: typeof admin;
  rules?: unknown[];
  dataplane?: unknown;
  coverage?: { status: number; json: unknown };
  health?: unknown;
  preview?: unknown;
  installed?: unknown;
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
    if (path === "/api/v1/dataplane/ics-coverage") {
      await route.fulfill(mocks.coverage ?? { status: 200, json: report });
      return;
    }
    if (path === "/api/v1/dataplane/ruleset") {
      // Admin-only and 400 on an invalid candidate: never the coverage source.
      seen.rulesetRequests++;
      await route.fulfill({ status: 403, json: { error: "forbidden" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
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
    if (path === "/api/v1/dataplane/ruleset/status") body = mocks.installed ?? { installed: true, appliedAt: "2026-10-26T06:00:00Z" };
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  return seen;
}

async function open(page: Page, path: string) {
  const loaded = Promise.all([
    page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/firewall/rules"),
    page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/dataplane/ics-coverage"),
  ]);
  await page.goto(path);
  await loaded;
}

async function inspectNotice(page: Page, message: string, detail: string) {
  const notice = page.getByRole("status").filter({ hasText: message });
  await expect(notice).toBeVisible();
  await expect(notice.getByText(detail, { exact: true })).toBeVisible();
}

function coverageOf(page: Page, ruleId: string) {
  return page.getByLabel(`ICS coverage of ${ruleId}`);
}

test("ICS page shows applied coverage for each state, never mode alone", async ({ page }) => {
  const seen = await mockAPI(page, {});
  await open(page, "/ics/");
  await expect(page.getByLabel("Active inspection state", { exact: true }).getByText("Partly active", { exact: true })).toBeVisible();

  const read = coverageOf(page, "plc-read");
  await expect(read.getByText("applied: enforcing")).toHaveClass(/badge-secure/);
  await expect(read.getByRole("status")).toHaveCount(1);

  const inherit = coverageOf(page, "plc-inherit");
  await expect(inherit.getByText("applied: partial")).toHaveClass(/badge-warning/);
  await expect(inherit).toContainText(`${exclusion.message} \u2014 7 connections exempted since the last apply`);
  // Applied match counts are not a candidate difference.
  await expect(inherit.getByText(/^candidate:/)).toHaveCount(0);

  const dnp3 = coverageOf(page, "dnp3-ops");
  await expect(dnp3.getByText("applied: not enforcing")).toHaveClass(/badge-critical/);
  await expect(dnp3.getByText(dpiOff.message, { exact: true })).toBeVisible();

  await expect(coverageOf(page, "plc-learn").getByText("applied: monitoring")).toHaveClass(/badge-offline/);

  const pending = coverageOf(page, "plc-pending");
  await expect(pending.getByText("not applied")).toHaveClass(/badge-offline/);
  await expect(pending.getByText("candidate: enforcing")).toBeVisible();

  // A configuration difference is drift: the candidate is shown.
  const drift = coverageOf(page, "plc-drift");
  await expect(drift.getByText("applied: not enforcing")).toHaveClass(/badge-critical/);
  await expect(drift).toContainText(decoderOff.message);
  await expect(drift.getByText("candidate: enforcing")).toBeVisible();

  // A runtime-only fault is an applied fact, not a pending change.
  const queue = coverageOf(page, "plc-queue");
  await expect(queue.getByText("applied: not enforcing")).toHaveClass(/badge-critical/);
  await expect(queue.getByText(`Live inspection: ${queueDown.message}`, { exact: true })).toBeVisible();
  await expect(queue.getByText(/^candidate:/)).toHaveCount(0);

  // The mode column states the effective mode with no protection colour.
  const inheritRow = page.getByRole("row").filter({ hasText: "plc-inherit" });
  await expect(inheritRow.getByText("Inherit (Enforce)")).toHaveClass(/badge-offline/);
  await expect(page.getByRole("row").filter({ hasText: "plc-learn" }).getByText("Monitor (safe)", { exact: true })).toHaveClass(/badge-offline/);

  // Green appears only on enforcing coverage (the DPI switch badge sits outside the table).
  await expect(page.locator("table .badge-secure")).toHaveText([
    "applied: enforcing",
    "candidate: enforcing",
    "candidate: enforcing",
  ]);
  await expect(page.getByText("Last activation attempt:", { exact: false })).toBeVisible();
  expect(seen.rulesetRequests).toBe(0);
  expect(seen.errors).toEqual([]);
});

test("ICS page shows the runtime aggregate and the NFQUEUE inline path", async ({ page }) => {
  await mockAPI(page, {});
  await open(page, "/ics/");

  await expect(page.getByRole("status", { name: /ICS protocol rules not enforcing/ })).toBeVisible();
  await expect(page.getByText("1 enforcing, 1 partial, 3 not enforcing, 1 monitoring")).toBeVisible();
  await expect(page.getByText("Inline inspection configured", { exact: true })).toBeVisible();
  const queue = page.getByText("Inline inspection queue (NFQUEUE): 101", { exact: true });
  await expect(page.getByRole("region", { name: "Candidate DPI Settings" }).getByRole("button", { name: "Technical details", exact: true })).toHaveAttribute("aria-expanded", "true");
  await expect(queue).toBeVisible();
  await expect(page.getByText("needs no capture interface", { exact: false })).toBeVisible();
  await expect(page.getByText("at least one capture interface")).toHaveCount(0);
});

for (const width of [1280, 390]) {
  test(`saved capture interfaces are visible without expanding details at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    await mockAPI(page, { dataplane: { dpiEnabled: true, nfqueueGroup: 0, captureInterfaces: ["eth0", "lan1"] } });
    await open(page, "/ics/");
    const interfaces = page.getByText("Capture interfaces: eth0, lan1", { exact: true });
    await expect(interfaces).toBeVisible();
    await expect(page.getByRole("region", { name: "Candidate DPI Settings" }).getByRole("button", { name: "Technical details", exact: true })).toHaveAttribute("aria-expanded", "true");
  });
}

test("default capture settings keep technical details collapsed", async ({ page }) => {
  await mockAPI(page, { dataplane: { dpiEnabled: true, nfqueueGroup: 0, captureInterfaces: [] } });
  await open(page, "/ics/");
  const queue = page.getByText("Inline inspection queue (NFQUEUE): 0", { exact: true });
  await expect(page.getByRole("region", { name: "Candidate DPI Settings" }).getByRole("button", { name: "Technical details", exact: true })).toHaveAttribute("aria-expanded", "false");
  await expect(queue).not.toBeVisible();
});

test("ICS page without an inline path says rules can only monitor", async ({ page }) => {
  await mockAPI(page, {
    dataplane: { dpiEnabled: true, captureInterfaces: ["lan1"] },
    health: { status: "ok", component: "mgmt", icsEnforcement: { state: "monitoring", monitoring: 6 } },
  });
  await open(page, "/ics/");
  await expect(page.getByText("Monitor only \u2014 inline inspection is not configured")).toBeVisible();
  await expect(page.getByRole("status", { name: /ICS protocol rules monitoring only/ })).toBeVisible();
});

test("health with an unknown engine says so", async ({ page }) => {
  await mockAPI(page, {
    health: { status: "ok", component: "mgmt", icsEnforcement: { state: "unknown", enforcing: 0, partial: 0, notEnforcing: 0, monitoring: 0 } },
  });
  await open(page, "/ics/");
  await expect(page.getByRole("status", { name: /ICS protocol enforcement/ })).toContainText("live inspection status unknown");
});

test("a coverage response without fields claims neither side and does not crash", async ({ page }) => {
  const seen = await mockAPI(page, { coverage: { status: 200, json: {} }, health: { status: "ok", component: "mgmt" } });
  await open(page, "/ics/");

  const read = coverageOf(page, "plc-read");
  await expect(read.getByText("applied: unknown")).toHaveClass(/badge-offline/);
  await expect(read.getByText("candidate: unavailable")).toHaveClass(/badge-offline/);
  await expect(page.getByText("not applied", { exact: true })).toHaveCount(0);
  await inspectNotice(page, "Saved ICS inspection coverage unavailable.", "not reported by the server");
  await inspectNotice(page, "Active ICS inspection coverage unknown.", "not reported by the server");
  await expect(page.locator("table .badge-secure")).toHaveCount(0);
  await expect(page.getByRole("status", { name: /ICS protocol enforcement/ })).toContainText("status unavailable");
  expect(seen.errors).toEqual([]);
});

test("an engine status error leaves applied unknown, never empty", async ({ page }) => {
  const seen = await mockAPI(page, {
    coverage: {
      status: 200,
      json: {
        candidate: [cov("plc-read", "partial", "enforce", [exclusion])],
        engineStatusError: "engine ruleset status unavailable: dial tcp 127.0.0.1:8081: connection refused",
      },
    },
  });
  await open(page, "/ics/");

  await inspectNotice(page, "Active ICS inspection coverage unknown.", "engine ruleset status unavailable: dial tcp 127.0.0.1:8081: connection refused");
  const read = coverageOf(page, "plc-read");
  await expect(read.getByText("applied: unknown")).toHaveClass(/badge-offline/);
  await expect(read.getByText("candidate: partial")).toHaveClass(/badge-warning/);
  await expect(coverageOf(page, "plc-inherit").getByText("applied: unknown")).toBeVisible();
  await expect(page.getByText("not applied", { exact: true })).toHaveCount(0);
  expect(seen.errors).toEqual([]);
});

test("a candidate error keeps the applied coverage and names the fault", async ({ page }) => {
  const seen = await mockAPI(page, {
    coverage: {
      status: 200,
      json: { candidateError: "rule plc-read: ics enforce requires dataplane.nfqueueGroup", applied },
    },
  });
  await open(page, "/ics/");

  await inspectNotice(page, "Saved ICS inspection coverage unavailable.", "rule plc-read: ics enforce requires dataplane.nfqueueGroup");
  const read = coverageOf(page, "plc-read");
  await expect(read.getByText("applied: enforcing")).toHaveClass(/badge-secure/);
  await expect(read.getByText("candidate: unavailable")).toHaveClass(/badge-offline/);
  await expect(coverageOf(page, "plc-queue").getByText("applied: not enforcing")).toBeVisible();
  expect(seen.rulesetRequests).toBe(0);
  expect(seen.errors).toEqual([]);
});

test("a failed apply is reported and applied coverage describes the previous rules", async ({ page }) => {
  await mockAPI(page, {
    coverage: { status: 200, json: { ...report, applyError: "nft: syntax error" } },
    installed: { installed: true, appliedAt: "2026-10-26T06:00:00Z", error: "nft: syntax error" },
  });
  await open(page, "/ics/");
  await expect(page.getByText("The last apply failed, so applied coverage describes the rules still in force from before it.", { exact: false })).toBeVisible();
  await expect(page.getByRole("status", { name: "Failed apply" })).toContainText("nft: syntax error");
  await expect(coverageOf(page, "plc-read").getByText("applied: enforcing")).toBeVisible();
  await expect(page.getByText("Last activation attempt:", { exact: false })).toBeVisible();
});

test("ICS inspection reports each installed apply and schedule fault once, without expanding", async ({ page }) => {
  const applyError = "nft: syntax error";
  const reason = "the schedule horizon ends within an hour";
  const lastError = "set refill: netlink busy";
  await mockAPI(page, {
    coverage: { status: 200, json: { ...report, applyError } },
    installed: {
      installed: true, error: applyError,
      schedulePlanner: { state: "degraded", reason, lastError },
    },
  });
  await open(page, "/ics/");
  for (const cause of [applyError, reason, lastError]) {
    const text = page.getByText(cause, { exact: false });
    await expect(text).toHaveCount(1);
    await expect(text).toBeVisible();
  }
  await expect(page.getByText("The last apply failed, so applied coverage describes the rules still in force from before it.", { exact: false })).toBeVisible();
});

for (const installedError of [undefined, "nft: a different apply failed"]) {
  test(`ICS inspection retains the coverage apply cause when installed status ${installedError ? "reports a different cause" : "is unavailable"}`, async ({ page }) => {
    const applyError = "nft: syntax error";
    await mockAPI(page, {
      coverage: { status: 200, json: { ...report, applyError } },
      installed: { installed: true, error: installedError },
    });
    if (!installedError) {
      await page.route("**/api/v1/dataplane/ruleset/status", route => route.fulfill({ status: 503, json: { error: "installed status offline" } }));
    }
    await open(page, "/ics/");
    await expect(page.getByText(applyError, { exact: true })).toHaveCount(1);
    await expect(page.getByText(applyError, { exact: true })).toBeVisible();
    if (installedError) await expect(page.getByText(installedError, { exact: true })).toBeVisible();
  });
}

test("an unreachable coverage route reports why and claims no coverage", async ({ page }) => {
  const seen = await mockAPI(page, { coverage: { status: 500, json: { error: "failed to load candidate" } } });
  await open(page, "/ics/");

  await inspectNotice(page, "ICS coverage unavailable.", "failed to load candidate");
  await expect(coverageOf(page, "plc-read").getByText("coverage unavailable")).toHaveClass(/badge-offline/);
  await expect(page.locator("table .badge-secure")).toHaveCount(0);
  expect(seen.errors).toEqual([]);
});

test("a viewer sees per-rule coverage without the admin-only ruleset", async ({ page }) => {
  const seen = await mockAPI(page, { user: viewer });
  await open(page, "/ics/");

  await expect(coverageOf(page, "plc-read").getByText("applied: enforcing")).toHaveClass(/badge-secure/);
  await expect(coverageOf(page, "plc-queue")).toContainText(`Live inspection: ${queueDown.message}`);
  await expect(page.getByRole("status", { name: /ICS protocol rules not enforcing/ })).toBeVisible();
  // Editing is admin-only; the server refuses a viewer's change anyway.
  await expect(page.getByRole("button", { name: "Edit", exact: true })).toHaveCount(0);
  expect(seen.rulesetRequests).toBe(0);
  expect(seen.errors).toEqual([]);
});

test("a viewer sees coverage in the firewall rules table", async ({ page }) => {
  const seen = await mockAPI(page, { user: viewer });
  await open(page, "/firewall/");

  await expect(coverageOf(page, "plc-inherit").getByText("applied: partial")).toHaveClass(/badge-warning/);
  await expect(coverageOf(page, "plc-queue").getByText(/^candidate:/)).toHaveCount(0);
  expect(seen.rulesetRequests).toBe(0);
  expect(seen.errors).toEqual([]);
});

test("firewall table labels an inherited mode by its effective mode", async ({ page }) => {
  await mockAPI(page, { dataplane: { dpiEnabled: true } });
  await open(page, "/firewall/");

  const inheritRow = page.getByRole("row").filter({ hasText: "plc-inherit" });
  await expect(inheritRow.getByText("Inherit (Monitor (safe))")).toHaveClass(/badge-offline/);
  await expect(inheritRow.getByText("Enforce", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("row").filter({ hasText: "plc-read" }).getByText("Enforce", { exact: true })).toBeVisible();
  await expect(page.getByRole("row").filter({ hasText: "plc-learn" }).getByText("Monitor (safe)", { exact: true })).toBeVisible();
});

test("firewall table shows coverage beside the effective mode", async ({ page }) => {
  const seen = await mockAPI(page, {});
  await open(page, "/firewall/");

  const inheritRow = page.getByRole("row").filter({ hasText: "plc-inherit" });
  await expect(inheritRow.getByText("Inherit (Enforce)")).toBeVisible();
  await expect(coverageOf(page, "plc-inherit").getByText("applied: partial")).toHaveClass(/badge-warning/);
  await expect(coverageOf(page, "dnp3-ops").getByText("applied: not enforcing")).toHaveClass(/badge-critical/);
  await expect(coverageOf(page, "plc-drift").getByText("candidate: enforcing")).toBeVisible();
  await expect(coverageOf(page, "plc-queue").getByText(/^candidate:/)).toHaveCount(0);
  await expect(coverageOf(page, "l4-only")).toHaveCount(0);
  expect(seen.errors).toEqual([]);
});

test("firewall without ICS protocol rules shows no coverage notice", async ({ page }) => {
  await mockAPI(page, { rules: [rules[7]], coverage: { status: 200, json: {} } });
  await open(page, "/firewall/");
  await expect(page.getByRole("row").filter({ hasText: "l4-only" })).toBeVisible();
  await expect(page.getByText("ICS coverage unknown", { exact: false })).toHaveCount(0);
  await expect(page.getByText("ICS coverage unavailable", { exact: false })).toHaveCount(0);
});

test("rule preview shows coverage in its own section, apart from rule warnings", async ({ page }) => {
  const warning = {
    ruleId: "plc-read",
    predicate: "identity",
    action: "ALLOW",
    message: "no bound address can match identities [historian]; the rule matches nothing until one is bound",
  };
  await mockAPI(page, {
    rules: [rules[0]],
    preview: {
      match_count: 3,
      sample_matches: [],
      time_range: null,
      total_events: 9,
      warnings: [warning],
      icsCoverage: cov("plc-read", "not_enforcing", "enforce", [dpiOff, queueDown]),
    },
  });
  await open(page, "/ics/");
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  await page.getByRole("button", { name: "Preview impact" }).click();

  const summary = page.getByLabel("Rule impact preview");
  const section = summary.getByLabel("ICS coverage", { exact: true });
  await expect(section.getByText("not enforcing", { exact: true })).toHaveClass(/badge-critical/);
  await expect(section).toContainText("mode in use: enforce");
  await expect(section).toContainText(dpiOff.message);
  await expect(section).toContainText(`Live inspection: ${queueDown.message}`);
  const warnings = summary.getByRole("status").filter({ hasText: "Rules that do not act as written" });
  await expect(warnings).toContainText(warning.message);
  await expect(warnings).not.toContainText(dpiOff.message);
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
  await expect(summary).toContainText("No recent events to search: none have been retained yet.");
  await expect(summary.getByLabel("ICS coverage", { exact: true })).toHaveCount(0);
  expect(seen.errors).toEqual([]);
});

for (const [state, expected] of [["enforcing", "Enforcing"], ["partial", "Partly active"], ["monitoring", "Monitoring"], ["unknown", "Unknown"], ["not_enforcing", "Not enforcing"]] as const) {
  test(`active inspection header: ${state} comes from applied coverage and health`, async ({ page }) => {
    const mode = state === "monitoring" ? "monitor" : "enforce";
    await mockAPI(page, {
      rules: [rules[0]],
      coverage: { status: 200, json: { candidate: [cov("plc-read", "enforcing")], applied: [cov("plc-read", state, mode)] } },
      health: { status: "ok", component: "mgmt", icsEnforcement: { state } },
    });
    await open(page, "/ics/");
    const header = page.getByLabel("Active inspection state", { exact: true });
    await expect(header.getByText(expected, { exact: true })).toBeVisible();
    if (state === "monitoring") {
      await expect(header).toContainText("monitor rules do not protect traffic");
      await expect(header.locator(".badge-secure")).toHaveCount(0);
    }
  });
}

for (const pending of [false, true]) {
  test(`active inspection names confirmed absence neutrally with ${pending ? "pending candidate rules" : "no candidate rules"}`, async ({ page }) => {
    await mockAPI(page, {
      rules: pending ? [rules[0]] : [],
      coverage: { status: 200, json: { candidate: pending ? [cov("plc-read", "enforcing")] : [], applied: [] } },
      health: { status: "ok", component: "mgmt", icsEnforcement: { state: "none" } },
    });
    await open(page, "/ics/");
    const header = page.getByLabel("Active inspection state", { exact: true });
    await expect(header.getByText("No ICS rules applied", { exact: true })).toHaveClass(/badge-offline/);
    await expect(header.locator(".badge-secure")).toHaveCount(0);
    if (pending) await expect(coverageOf(page, "plc-read").getByText("not applied", { exact: true })).toBeVisible();
  });
}

for (const observation of ["missing applied coverage", "conflicting applied coverage", "unknown health"] as const) {
  test(`active inspection does not claim absence with ${observation}`, async ({ page }) => {
    await mockAPI(page, {
      coverage: { status: 200, json: {
        candidate: [],
        ...(observation === "missing applied coverage" ? {} : { applied: observation === "conflicting applied coverage" ? [cov("plc-read", "enforcing")] : [] }),
      } },
      health: { status: "ok", component: "mgmt", icsEnforcement: { state: observation === "unknown health" ? "unknown" : "none" } },
    });
    await open(page, "/ics/");
    const header = page.getByLabel("Active inspection state", { exact: true });
    await expect(header.getByText("Unknown", { exact: true })).toBeVisible();
    await expect(header.getByText("No ICS rules applied", { exact: true })).toHaveCount(0);
  });
}

for (const endpoint of ["health", "dataplane/ics-coverage"]) {
  test(`active inspection header is unknown after failed ${endpoint} read`, async ({ page }) => {
    await mockAPI(page, {
      health: { status: "ok", component: "mgmt", icsEnforcement: { state: "enforcing", enforcing: 1 } },
      coverage: { status: 200, json: { candidate: [cov("plc-read", "enforcing")], applied: [cov("plc-read", "enforcing")] } },
    });
    await page.route(`**/api/v1/${endpoint}`, route => route.fulfill({ status: 503, json: { error: "inspection service offline" } }));
    await open(page, "/ics/");
    await expect(page.getByLabel("Active inspection state", { exact: true }).getByText("Unknown", { exact: true })).toBeVisible();
    if (endpoint !== "health") await expect(page.getByText("inspection service offline", { exact: true })).toBeVisible();
  });
}

for (const conflict of [true, false]) {
  test(`active inspection ${conflict ? "does not resolve contradictory observations into protection" : "keeps monitor rules distinct alongside enforcing rules"}`, async ({ page }) => {
    await mockAPI(page, {
      coverage: { status: 200, json: { candidate: [], applied: [cov("plc-read", conflict ? "not_enforcing" : "enforcing"), cov("plc-learn", "monitoring", "monitor")] } },
      health: { status: "ok", component: "mgmt", icsEnforcement: { state: "enforcing", enforcing: 1, monitoring: 1 } },
    });
    await open(page, "/ics/");
    await expect(page.getByLabel("Active inspection state", { exact: true }).getByText(conflict ? "Unknown" : "Enforcing", { exact: true })).toBeVisible();
    await expect(page.getByRole("row").filter({ has: page.getByRole("cell", { name: "plc-learn", exact: true }) }).getByText("Observation only — non-blocking", { exact: true })).toBeVisible();
  });
}

test("Why? reveals full applied and candidate reasons without inventing drift", async ({ page }) => {
  await mockAPI(page, {});
  await open(page, "/ics/");
  const coverage = coverageOf(page, "plc-inherit");
  await expect(coverage.getByText(/^candidate:/)).toHaveCount(0);
  await expect(coverage).toContainText("7 connections exempted since the last apply");
  const why = coverage.getByRole("button", { name: "Why?", exact: true });
  await why.focus();
  await page.keyboard.press("Enter");
  await expect(why).toHaveAttribute("aria-expanded", "true");
  const detail = page.locator(`[id="${await why.getAttribute("aria-controls")}"]`);
  await expect(detail).toContainText("Applied: partial");
  await expect(detail).toContainText("Candidate: partial");
  await expect(detail).toContainText(exclusion.message);
  await page.keyboard.press("Space");
  await expect(why).toHaveAttribute("aria-expanded", "false");
  await expect(why).toBeFocused();
});

test("ICS read-only inspection remains operable after a failed refresh disables saving", async ({ page }) => {
  await mockAPI(page, { rules: [rules[1]] });
  await open(page, "/ics/");
  const row = page.getByRole("row").filter({ has: page.getByRole("cell", { name: "plc-inherit", exact: true }) });
  const inspect = row.getByRole("button", { name: "Inspect rule", exact: true });
  await expect(inspect).toHaveAttribute("aria-expanded", "true");
  await inspect.click();
  await expect(inspect).toHaveAttribute("aria-expanded", "false");

  await page.route("**/api/v1/dataplane", route => route.fulfill({ status: 503, json: { error: "settings unavailable" } }));
  const failed = page.waitForResponse("**/api/v1/dataplane");
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await failed;
  await expect(page.getByRole("alert").filter({ hasText: "Configuration unavailable." })).toBeVisible();

  await inspect.focus();
  await page.keyboard.press("Enter");
  await expect(inspect).toHaveAttribute("aria-expanded", "true");
  await expect(row.getByText("Codes", { exact: true })).toBeVisible();
  const why = row.getByRole("button", { name: "Why?", exact: true });
  await why.focus();
  await page.keyboard.press("Enter");
  await expect(why).toHaveAttribute("aria-expanded", "true");
  await expect(row.getByText("Applied: partial", { exact: true })).toBeVisible();

  const details = page.getByRole("button", { name: "Inspection details", exact: true });
  await details.click();
  await expect(details).toHaveAttribute("aria-expanded", "true");
  await row.getByRole("button", { name: "Edit", exact: true }).click();
  await expect(page.getByRole("button", { name: "Save filter", exact: true })).toBeDisabled();
});

test("compact rules retain all matching fields and keyboard inspection at 390px", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockAPI(page, { rules: [icsRule("matching", "modbus", "enforce"), { id: "wildcard", action: "ALLOW", ics: { protocol: "modbus" } }] });
  await open(page, "/ics/");
  const matching = page.getByRole("row").filter({ has: page.getByRole("cell", { name: "matching", exact: true }) });
  await expect(matching.getByRole("button", { name: "Inspect rule" })).toHaveAttribute("aria-expanded", "true");
  await expect(matching.getByText("Matching constraints", { exact: true })).toBeVisible();
  const wildcard = page.getByRole("row").filter({ has: page.getByRole("cell", { name: "wildcard", exact: true }) });
  const button = wildcard.getByRole("button", { name: "Inspect rule" });
  await expect(button).toHaveAttribute("aria-expanded", "false");
  await button.focus();
  await page.keyboard.press("Enter");
  for (const label of ["Codes", "Addresses", "R/W"]) {
    await expect(wildcard.getByText(label, { exact: true }).first()).toBeVisible();
  }
  await page.keyboard.press("Space");
  await expect(button).toHaveAttribute("aria-expanded", "false");
  await expect(button).toBeFocused();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

for (const empty of [true, false]) {
  test(`Inspection setup starts ${empty ? "open for the first empty state" : "collapsed for configured rules"}`, async ({ page }) => {
    await mockAPI(page, { rules: empty ? [] : rules });
    await open(page, "/ics/");
    const button = page.getByRole("button", { name: "Inspection setup", exact: true });
    await expect(button).toHaveAttribute("aria-expanded", String(empty));
    if (!empty) await button.click();
    await expect(page.getByRole("region", { name: "Supported Protocols", exact: true })).toBeVisible();
    await expect(page.getByRole("region", { name: "Quick Start", exact: true })).toBeVisible();
    await expect(page.getByRole("link", { name: "Go to Firewall Rules", exact: false })).toBeVisible();
  });
}
