import { expect, test } from "@playwright/test";

import { describeICSEvidence } from "../app/events/iec104-evidence";
import type { TelemetryEvent } from "../lib/api";

const session = "0123456789abcdef0123456789abcdef-1";
const types = {
  iec104_data_while_stopped: "IEC 104 data transfer not started",
  iec104_send_sequence: "IEC 104 send sequence anomaly",
  iec104_ack_sequence: "IEC 104 acknowledgement anomaly",
  iec104_test_timeout: "IEC 104 TESTFR confirmation timeout",
};

function event(anomalyType: string): TelemetryEvent {
  return {
    id: 1, flowId: "iec-flow", proto: "ids", kind: "anomaly",
    timestamp: "2026-10-26T12:00:00Z",
    srcIp: "10.0.0.1", dstIp: "10.0.0.2", srcPort: 40000, dstPort: 2404, transport: "tcp",
    attributes: {
      anomaly_type: anomalyType, protocol: "iec104", severity: "medium",
      session_id: session, direction: "request", apci_type: "I",
      send_sequence: 3, expected_send_sequence: 1,
    },
  };
}

for (const [type, label] of Object.entries(types)) {
  test(`${type} has an observational label and session evidence`, () => {
    const view = describeICSEvidence(event(type));
    expect(view?.headline).toBe(label);
    expect(view?.alert).toBe(true);
    expect(view?.badge).toBe("observation");
    expect(view?.sessionId).toBe(session);
    expect(view?.rows).toContainEqual({ label: "N(S)", value: "3" });
    expect(view?.rows).toContainEqual({ label: "Expected N(S)", value: "1" });
  });
}

test("APCI anomaly appears in Alerts with readable type and session link", async ({ page }, testInfo) => {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const user = { id: "admin-1", username: "containd", role: "admin" };
    let body: unknown = {};
    if (path.endsWith("/auth/me") || path.endsWith("/auth/session")) body = user;
    else if (path.endsWith("/events")) body = [event("iec104_send_sequence")];
    else if (path.endsWith("/system/info")) body = { version: "0.1.35", hostname: "containd" };
    await route.fulfill({ contentType: "application/json", body: JSON.stringify(body) });
  });
  await page.goto("/alerts/");
  await page.getByRole("cell", { name: "IEC 104 send sequence anomaly", exact: true }).click();
  await expect(page.getByRole("heading", { name: "IEC 104 send sequence anomaly" })).toBeVisible();
  await expect(page.getByText("observation", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Open session events" })).toHaveAttribute(
    "href", `/events/?session=${session}`,
  );
  await page.screenshot({ path: testInfo.outputPath("apci-alert.png"), fullPage: true });
});
