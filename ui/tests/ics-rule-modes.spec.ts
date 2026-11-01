import { expect, test, type Page } from "@playwright/test";
import { normalizeShadowCounters } from "../lib/api-shadow-counters";
import { formatICSMode } from "../app/ics/ics-shared";
import { describeICSEvidence } from "../app/events/iec104-evidence";

const since = "2026-10-30T12:00:00Z";
const snapshot = {
  available: true, snapshotVersion: "snapshot-1", since, unit: "messages",
  rules: [
    { ruleId: "trial", shadowMatches: 12, wouldAllow: 10, wouldDeny: 2 },
    { ruleId: "zero", shadowMatches: 0, wouldAllow: 0, wouldDeny: 0 },
  ],
};
const rules = [
  { id: "trial", action: "ALLOW", ics: { protocol: "modbus", mode: "monitor" } },
  { id: "zero", action: "DENY", ics: { protocol: "iec104", mode: "monitor" } },
  { id: "pending", action: "DENY", ics: { protocol: "modbus", mode: "monitor" } },
  { id: "active", action: "DENY", ics: { protocol: "modbus", mode: "enforce" } },
  { id: "plain", action: "ALLOW" },
];

test("mode resolution uses independent rule overrides and a safe default", () => {
  for (const global of [undefined, "", "monitor", "enforce"]) {
    expect(formatICSMode("monitor", global).effectiveMode).toBe("monitor");
    expect(formatICSMode("enforce", global).effectiveMode).toBe("enforce");
  }
  expect(formatICSMode("", "enforce")).toMatchObject({ effectiveMode: "enforce", inherited: true });
  expect(formatICSMode(undefined, undefined).effectiveMode).toBe("monitor");
});

test("shadow counter normalization preserves zero and never fabricates availability", () => {
  expect(normalizeShadowCounters(snapshot)).toEqual(snapshot);
  expect(normalizeShadowCounters({ available: false, reason: "no apply" })).toEqual({ available: false, reason: "no apply" });
  for (const malformed of [{}, { ...snapshot, unit: "objects" }, { ...snapshot, since: "bad" },
    { ...snapshot, rules: [{ ruleId: "trial", shadowMatches: 0 }] },
    { ...snapshot, rules: [{ ruleId: "trial", shadowMatches: -1, wouldAllow: 0, wouldDeny: 0 }] }]) {
    expect(normalizeShadowCounters(malformed).available).toBe(false);
  }
});

test("generic and IEC shadow evidence never claims delivery; would-allow is not an alert", () => {
  for (const proto of ["modbus", "iec104", "dnp3", "cip"]) {
    for (const decision of ["would_allow", "would_drop"]) {
      const evidence = describeICSEvidence({ id: "1", flowId: "flow-1", timestamp: since, kind: "ics.decision", proto,
        attributes: { decision, mode: "monitor", ruleId: "trial", action: "ALLOW", reason: "rule" } });
      expect(evidence?.headline).toContain("monitor");
      expect(evidence?.badge).toBe(decision === "would_allow" ? "would allow" : "would drop");
      expect(evidence?.alert).toBe(decision === "would_drop");
      expect(evidence?.rows).toContainEqual({ label: "Rule", value: "trial" });
    }
  }
});

test("strict scope evidence does not attribute the drop to a monitor rule", () => {
  const evidence = describeICSEvidence({ id: "1", flowId: "flow-1", timestamp: since, proto: "iec104", kind: "ics.decision",
    attributes: { decision: "deny", reason: "nonconformant", scopeId: "scope-1", findingCode: "iec104.role", mode: "enforce" } });
  expect(evidence?.rows).toContainEqual({ label: "Scope", value: "scope-1" });
  expect(evidence?.rows).toContainEqual({ label: "Finding", value: "iec104.role" });
  expect(evidence?.rows.some((row) => row.label === "Rule" || row.label === "Rule action")).toBe(false);
});

async function mock(page: Page, counters: unknown = snapshot) {
  const writes: { path: string; body: Record<string, unknown> }[] = [];
  const queries: URL[] = [];
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    const path = url.pathname;
    let body: unknown = {};
    if (req.method() === "POST" || req.method() === "PATCH") {
      const sent = req.postDataJSON();
      writes.push({ path, body: sent });
      body = path === "/api/v1/templates/ics/apply" ? { rules: [], created: 0 } : sent;
    } else if (path.endsWith("/auth/me") || path.endsWith("/auth/session")) body = { id: "admin", username: "containd", role: "admin" };
    else if (path === "/api/v1/firewall/rules") body = rules;
    else if (path === "/api/v1/firewall/shadow-counters") body = typeof counters === "function" ? counters() : counters;
    else if (path === "/api/v1/zones") body = [{ name: "lan" }, { name: "ot" }];
    else if (path === "/api/v1/routing") body = { routes: [], gateways: [], rules: [] };
    else if (path === "/api/v1/dataplane") body = { dpiEnabled: true, dpiMode: "enforce", nfqueueGroup: 101 };
    else if (path === "/api/v1/templates/ics") body = [{ name: "modbus_read_only", protocol: "modbus", description: "Read baseline" }];
    else if (path === "/api/v1/events") {
      queries.push(url);
      body = { historyTruncated: false, events: ["would_allow", "would_drop"].map((decision, i) => ({
        id: i + 1, flowId: `flow-${i}`, timestamp: since, kind: "ics.decision", proto: i ? "iec104" : "modbus",
        attributes: { decision, reason: "rule", mode: "monitor", ruleId: "trial", action: i ? "DENY" : "ALLOW" },
      })) };
    }
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  return { writes, queries };
}

for (const path of ["/ics/", "/firewall/"]) {
  test(`${path} shows applied counts, pending and unavailable distinctly, and links filtered evidence`, async ({ page }) => {
    const seen = await mock(page);
    const loaded = page.waitForResponse((r) => r.url().includes("firewall/shadow-counters"));
    await page.goto(path);
    await loaded;
    await expect(page.getByRole("status", { name: "Shadow counters" })).toContainText(`Messages matched since ${since}`);
    const trial = page.getByLabel("Shadow matches of trial", { exact: true });
    await expect(trial).toContainText("12 messages");
    await expect(trial).toContainText("10 would allow · 2 would deny");
    await expect(trial).not.toContainText("Applied policy");
    await expect(page.getByLabel("Shadow matches of zero", { exact: true })).toContainText("0 messages");
    await expect(page.getByLabel("Shadow matches of pending", { exact: true })).toContainText("not applied yet");
    await expect(page.getByLabel("Shadow matches of pending", { exact: true }).getByRole("link", { name: "Monitor events" })).toBeVisible();
    if (process.env.RULE_MODES_SCREENSHOTS) {
      await page.screenshot({ path: `${process.env.RULE_MODES_SCREENSHOTS}/${path.replaceAll("/", "")}-shadow.png`, fullPage: true, animations: "disabled" });
    }
    await trial.getByRole("link", { name: "Monitor events" }).click();
    await expect.poll(() => seen.queries.some((url) => url.searchParams.get("kind") === "ics.decision" && url.searchParams.get("mode") === "monitor" && url.searchParams.get("ruleId") === "trial")).toBe(true);
    await expect(page.getByLabel("Rule ID", { exact: true })).toHaveValue("trial");
    await expect(page.getByLabel("Mode", { exact: true })).toHaveValue("monitor");
    await expect(page.getByText("MODBUS message: would allow (monitor)", { exact: true })).toBeVisible();
    await expect(page.getByText("IEC 104 APDU would be denied (monitor)", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Clear filters", exact: true }).click();
    await expect(page.getByLabel("Rule ID", { exact: true })).toHaveValue("");
  });

  test(`${path} engine unavailable is never shown as zero`, async ({ page }) => {
    await mock(page, { available: false, reason: "engine unreachable" });
    const loaded = page.waitForResponse((r) => r.url().includes("firewall/shadow-counters"));
    await page.goto(path);
    await loaded;
    const note = page.getByRole("status", { name: "Shadow counters" });
    await expect(note).toContainText("Monitor counts unavailable.");
    await expect(note.getByText("engine unreachable", { exact: true })).toBeVisible();
    await expect(page.getByLabel("Shadow matches of trial", { exact: true })).toContainText("unavailable");
    await expect(page.getByLabel("Shadow matches of trial", { exact: true })).not.toContainText("0 messages");
  });
}

test("global DPI mode stages inherit and monitor without changing explicit rules", async ({ page }) => {
  const seen = await mock(page);
  await page.goto("/firewall/");
  const mode = page.getByLabel("ICS DPI Mode", { exact: true });
  await expect(mode).toHaveValue("enforce");
  await mode.selectOption("monitor");
  await expect.poll(() => seen.writes.length).toBe(1);
  expect(seen.writes[0]).toMatchObject({ path: "/api/v1/dataplane", body: { dpiMode: "monitor", nfqueueGroup: 101 } });
  await mode.selectOption("");
  await expect.poll(() => seen.writes.length).toBe(2);
  expect(seen.writes[1].body.dpiMode).toBe("");
  await expect(page.getByRole("row").filter({ hasText: "active" }).getByText("Enforce", { exact: true })).toBeVisible();
});

test("templates send the same mode override for preview and staging", async ({ page }) => {
  const seen = await mock(page);
  await page.goto("/templates/");
  await page.getByRole("button", { name: "Generate Rules" }).click();
  const mode = page.getByLabel("Rule Mode", { exact: true });
  await expect(mode.locator("option:checked")).toHaveText("Inherit (Enforce)");
  await mode.selectOption("monitor");
  await page.getByRole("button", { name: "Preview", exact: true }).click();
  await expect.poll(() => seen.writes.length).toBe(1);
  await page.getByRole("button", { name: "Stage", exact: true }).click();
  await expect.poll(() => seen.writes.length).toBe(2);
  expect(seen.writes.map((write) => write.body)).toEqual([
    { template: "modbus_read_only", mode: "monitor", preview: true },
    { template: "modbus_read_only", mode: "monitor" },
  ]);
});

for (const mode of ["", "monitor", "enforce"]) {
  test(`wizard separates access from ${mode || "inherited"} mode`, async ({ page }) => {
    const seen = await mock(page);
    await page.goto("/wizard/");
    await page.getByRole("button", { name: /Allow ICS Communication/ }).click();
    await page.getByRole("button", { name: "Next", exact: true }).click();
    await page.getByRole("combobox").nth(0).selectOption("lan");
    await page.getByRole("combobox").nth(1).selectOption("ot");
    await page.getByRole("button", { name: "Next", exact: true }).click();
    await page.getByLabel("Rule Mode", { exact: true }).selectOption(mode);
    await page.getByRole("button", { name: "Next", exact: true }).click();
    await page.getByRole("button", { name: "Stage", exact: true }).click();
    await expect.poll(() => seen.writes.length).toBe(1);
    expect(seen.writes[0].body.ics).toEqual({ protocol: "modbus", readOnly: true, ...(mode ? { mode } : {}) });
  });
}

test("removing an ICS filter hides its mode selector", async ({ page }) => {
  await mock(page);
  await page.goto("/ics/");
  await page.getByRole("row").filter({ hasText: "trial" }).getByRole("button", { name: "Edit", exact: true }).click();
  await expect(page.getByLabel("Safety mode", { exact: true })).toHaveValue("monitor");
  await page.getByLabel("Enable ICS protocol filter").uncheck();
  await expect(page.getByLabel("Safety mode", { exact: true })).toHaveCount(0);
});

for (const path of ["/ics/", "/firewall/"]) {
  test(`${path} refresh keeps applied counts until a new snapshot arrives and clears unavailable data`, async ({ page }) => {
    let current: unknown = snapshot;
    await mock(page, () => current);
    await page.goto(path);
    const trial = page.getByLabel("Shadow matches of trial", { exact: true });
    await expect(trial).toContainText("12 messages");
    // Candidate refresh or a failed apply still returns the installed snapshot.
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(trial).toContainText("12 messages");
    const nextSince = "2026-10-30T13:00:00Z";
    current = { ...snapshot, snapshotVersion: "snapshot-2", since: nextSince,
      rules: snapshot.rules.map((r) => ({ ...r, shadowMatches: 0, wouldAllow: 0, wouldDeny: 0 })) };
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(trial).toContainText("0 messages");
    await expect(page.getByRole("status", { name: "Shadow counters" })).toContainText(nextSince);
    current = { available: false, reason: "before first apply" };
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(trial).toContainText("unavailable");
    await expect(trial).not.toContainText("0 messages");
  });
}

test("candidate promotion preserves applied monitor counts without a repeated policy label", async ({ page }) => {
  await mock(page, { ...snapshot, rules: [...snapshot.rules,
    { ruleId: "active", shadowMatches: 3, wouldAllow: 0, wouldDeny: 3 }] });
  await page.goto("/ics/");
  const active = page.getByRole("row").filter({ has: page.getByRole("cell", { name: "active", exact: true }) });
  await expect(active.getByText("Enforce", { exact: true })).toBeVisible();
  await expect(active.getByLabel("Shadow matches of active", { exact: true })).toContainText("3 messages");
  await expect(active.getByLabel("Shadow matches of active", { exact: true })).not.toContainText("Applied policy");
  await expect(active.getByRole("link", { name: "Monitor events" })).toBeVisible();
});

for (const path of ["/ics/", "/firewall/"]) {
  test(`${path} changing one rule's mode sends only that rule's PATCH`, async ({ page }) => {
    const seen = await mock(page);
    await page.goto(path);
    await page.getByRole("row").filter({ has: page.getByRole("cell", { name: "trial", exact: true }) })
      .getByRole("button", { name: "Edit", exact: true }).click();
    await page.getByLabel(path === "/ics/" ? "Safety mode" : "Rule Mode", { exact: true }).selectOption("enforce");
    await page.getByRole("button", { name: path === "/ics/" ? "Save filter" : "Save changes", exact: true }).click();
    await expect.poll(() => seen.writes.length).toBe(1);
    expect(seen.writes[0].path).toBe("/api/v1/firewall/rules/trial");
    expect(seen.writes[0].body.ics).toMatchObject({ mode: "enforce", protocol: "modbus" });
  });
}
