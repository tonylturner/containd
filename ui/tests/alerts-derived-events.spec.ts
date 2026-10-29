import { expect, test, type Page } from "@playwright/test";

import { alertView } from "../app/alerts/alert-view";
import type { TelemetryEvent } from "../lib/api";

const session = "0123456789abcdef0123456789abcdef-1";
const anomalyMessage = "Modbus response (txn 123) without prior request";
const signatureName = "CIP controller stop signature";

function event(id: number, kind: string, attributes: Record<string, unknown>): TelemetryEvent {
  return {
    id, flowId: `flow-${id}`, proto: "ids", kind, attributes,
    timestamp: "2026-10-28T12:00:00Z",
    srcIp: "192.0.2.10", dstIp: "192.0.2.20",
    srcPort: 49152, dstPort: 502, transport: "tcp",
  };
}

// Derived fixtures carry only the attributes supplied by their producers.
// In particular, the CIP signature has no message, protocol or event_attrs.
const anomaly = {
  ...event(1, "anomaly", {
    message: anomalyMessage, severity: "medium", protocol: "modbus",
    anomaly_type: "protocol_violation", source_ip: "192.0.2.20", dest_ip: "192.0.2.10",
  }),
  srcIp: "192.0.2.20", dstIp: "192.0.2.10", srcPort: 502, dstPort: 49152,
};
const signature = {
  ...event(2, "signature_match", {
    signature_id: "CIP-STOP-001", name: signatureName, severity: "critical",
    description: "Detects a controller stop service request.",
  }),
  dstPort: 44818,
};
const rule = event(3, "alert", {
  message: "Modbus write detected", severity: "low", rule_id: "MB-WRITE-001",
  event_proto: "modbus", event_kind: "request",
  event_attrs: { function_code: 6, unit_id: 1, is_write: true, address: 1, value: 3 },
});
const apci = {
  ...event(4, "anomaly", {
    anomaly_type: "iec104_send_sequence", protocol: "iec104", severity: "medium",
    message: "IEC 104 send sequence anomaly", session_id: session,
    direction: "request", apci_type: "I", send_sequence: 3, expected_send_sequence: 1,
  }),
  dstPort: 2404,
};
const deny: TelemetryEvent = {
  ...event(5, "ics.decision", {
    session_id: session, apdu_id: `${session}/c/16`, decision: "deny",
    reason: "rule", action: "DENY", mode: "enforce", ruleId: "deny-rule",
    type_id: 46, ca: 1, ioa: 2001, direction: "request",
  }),
  proto: "iec104", dstPort: 2404,
};
const conformance = event(6, "alert", {
  message: "modbus conformance modbus.length: passed", severity: "medium", rule_id: "ics-conformance",
  protocol: "modbus", action: "passed", conformance: ["modbus.length"],
});
const allow = {
  ...deny, id: 7,
  attributes: { ...deny.attributes, decision: "allow", action: "ALLOW" },
};
const request = { ...event(8, "request", { function_code: 3 }), proto: "modbus" };
const events = [anomaly, signature, rule, apci, deny, conformance, allow, request];

async function loadAlerts(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const json = path === "/api/v1/events" ? events
      : path.endsWith("/auth/me") || path.endsWith("/auth/session")
        ? { id: "admin", username: "containd", role: "admin" }
        : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json });
  });
  const answered = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/events");
  await page.goto("/alerts/");
  await answered;
  await expect(page.locator("tbody tr")).toHaveCount(6);
}

function row(page: Page, label: string) {
  return page.locator("div.flex.justify-between").filter({ has: page.getByText(label, { exact: true }) });
}

test("derived alerts show their real messages, identifiers and detail fields", async ({ page }, testInfo) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (err) => pageErrors.push(String(err)));
  await page.setViewportSize({ width: 1440, height: 1000 });
  await loadAlerts(page);
  for (const [severity, count] of [["critical", 1], ["high", 1], ["medium", 3], ["low", 1]]) {
    await expect(page.getByRole("button", { name: `${severity} ${count}`, exact: true })).toBeVisible();
  }
  await page.screenshot({ path: testInfo.outputPath("alerts-list.png"), fullPage: true });

  await page.getByRole("cell", { name: signatureName, exact: true }).click();
  await expect(page.getByRole("heading", { name: signatureName, exact: true })).toBeVisible();
  await expect(row(page, "Signature ID")).toContainText("CIP-STOP-001");
  await expect(row(page, "Description")).toContainText("Detects a controller stop service request.");
  await expect(page.getByText("Rule ID", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Triggered by", { exact: true })).toHaveCount(0);
  await expect(page.getByText("CIP/EtherNet/IP Analysis", { exact: true })).toHaveCount(0);
  // A service port does not supply protocol provenance for a signature match.
  await expect(page.getByText("cip", { exact: true })).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath("alerts-signature-detail.png"), fullPage: true });

  await page.getByRole("cell", { name: anomalyMessage, exact: true }).click();
  await expect(page.getByRole("heading", { name: anomalyMessage, exact: true })).toBeVisible();
  await expect(row(page, "Anomaly type")).toContainText("protocol_violation");
  await expect(page.getByText("modbus", { exact: true })).toBeVisible();
  for (const label of ["Rule ID", "Triggered by", "Transaction ID", "Modbus Protocol Analysis"]) {
    await expect(page.getByText(label, { exact: true })).toHaveCount(0);
  }

  await page.getByRole("cell", { name: "Modbus write detected", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Modbus write detected", exact: true })).toBeVisible();
  await expect(row(page, "Rule ID")).toContainText("MB-WRITE-001");
  await expect(row(page, "Triggered by")).toContainText("modbus / request");
  await expect(row(page, "Value")).toContainText("3 (0x0003)");

  await page.getByRole("cell", { name: "modbus conformance modbus.length: passed", exact: true }).click();
  await expect(row(page, "Rule ID")).toContainText("ics-conformance");
  await expect(page.getByText("modbus", { exact: true })).toBeVisible();
  await expect(page.getByText("Triggered by", { exact: true })).toHaveCount(0);

  await page.getByRole("cell", { name: "IEC 104 send sequence anomaly", exact: true }).click();
  await expect(page.getByText("observation", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Open session events" }))
    .toHaveAttribute("href", `/events/?session=${session}`);
  await page.getByRole("cell", { name: /deny: type 46/ }).click();
  await expect(page.getByRole("heading", { name: "IEC 104 APDU denied", exact: true })).toBeVisible();
  await expect(page.getByText("IEC 104 Evidence", { exact: true })).toBeVisible();
  expect(pageErrors).toEqual([]);
});

test("derived alert search and severity filters use the same presentation as the list", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (err) => pageErrors.push(String(err)));
  await loadAlerts(page);
  const search = page.getByPlaceholder("Search alerts by message, ID, anomaly type, IP...");
  for (const [query, message] of [
    ["cip-stop-001", signatureName],
    ["controller stop service", signatureName],
    ["protocol_violation", anomalyMessage],
    ["mb-write-001", "Modbus write detected"],
  ]) {
    await search.fill(query);
    await expect(page.locator("tbody tr")).toHaveCount(1);
    await expect(page.getByRole("cell", { name: message, exact: true })).toBeVisible();
  }
  await search.fill("modbus");
  await expect(page.locator("tbody tr")).toHaveCount(3);
  await search.fill("192.0.2.10");
  await expect(page.locator("tbody tr")).toHaveCount(6);
  await search.fill("");
  await page.getByRole("button", { name: "critical 1", exact: true }).click();
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await expect(page.getByRole("cell", { name: signatureName, exact: true })).toBeVisible();
  await page.getByRole("button", { name: "critical 1", exact: true }).click();
  await page.getByRole("button", { name: "medium 3", exact: true }).click();
  await expect(page.locator("tbody tr")).toHaveCount(3);
  await expect(page.getByRole("cell", { name: anomalyMessage, exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "IEC 104 send sequence anomaly", exact: true })).toBeVisible();
  expect(pageErrors).toEqual([]);
});

test("presentation normalizes severity and excludes allows and ordinary protocol events", () => {
  for (const [input, expected] of [
    [" CRITICAL ", "critical"], ["High", "high"], ["MEDIUM", "medium"],
    ["low", "low"], ["unknown", "low"], [undefined, "low"],
  ]) {
    expect(alertView({ ...signature, attributes: { ...signature.attributes, severity: input } })?.severity)
      .toBe(expected);
  }
  expect(alertView(allow)).toBeNull();
  expect(alertView(request)).toBeNull();
  expect(alertView(event(9, "other", {}))).toBeNull();
  for (const kind of ["alert", "anomaly", "signature_match"]) {
    const view = alertView(event(10, kind, {}));
    expect(view?.identifier).toBeUndefined();
    expect(view?.triggeredBy).toBe("");
    expect(view?.protocol).toBe("");
  }
});
