import { expect, test, type Page } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import type { IdentificationAttributes } from "../lib/api";

const identification: IdentificationAttributes = {
  protocol: "modbus", identification_state: "confirmed", reason: "paired frames",
  identification_candidates: ["modbus"],
  expected: ["", "dnp3"], service_transport: "tcp", service_port: 20000,
  mismatch: true, binding: "observation", outside_rule_port_scope: true,
  profile_version: 2, syn_coverage: [true, true],
};
const flow = {
  flowId: "10.0.0.1|10.0.0.2|49152|20000|006|0", firstSeen: "2026-10-29T08:00:00Z", lastSeen: "2026-10-29T08:01:00Z",
  srcIp: "10.0.0.1", dstIp: "10.0.0.2", srcPort: 49152, dstPort: 20000, transport: "tcp",
  application: "modbus", eventCount: 3, identification,
};

async function mockAPI(page: Page) {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    // The payload is consumed before recording/answering an analysis request.
    if (route.request().method() === "POST") route.request().postDataBuffer();
    const body = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin", username: "containd", role: "admin" }
      : path === "/api/v1/flows" ? [flow, { ...flow, flowId: "port-control", identification: undefined, application: "dnp3" }]
      : path === "/api/v1/events" ? { events: [
          { id: 1, flowId: flow.flowId, proto: "identify", kind: "identification", timestamp: flow.firstSeen, attributes: identification },
          { id: 2, flowId: flow.flowId, proto: "modbus", kind: "request", timestamp: flow.lastSeen, attributes: { observation_only: true, binding_source: "observation", function_code: 3 } },
        ], historyTruncated: false }
      : path === "/api/v1/pcap/list" ? [{ name: "alternate.pcap", sizeBytes: 400, createdAt: flow.firstSeen }]
      : path === "/api/v1/pcap/analyze/alternate.pcap" ? {
          rules: [], profiles: [], eventSummary: { modbus: 2 },
          stats: { events: [], flows: [], protocols: { modbus: 2 }, duration: 100000000, packetCount: 5, byteCount: 400,
            truncated: new URL(page.url()).searchParams.get("truncated") === "true",
            identifications: [
              { key: "capture/1", flowId: flow.flowId, srcIp: flow.srcIp, dstIp: flow.dstIp, srcPort: flow.srcPort, dstPort: flow.dstPort, attributes: identification },
              { key: "capture/2", flowId: "2001:db8::1|2001:db8::2|49153|1502|006|0", srcIp: "2001:db8::1", dstIp: "2001:db8::2", srcPort: 49153, dstPort: 1502, attributes: { ...identification, protocol: "", identification_state: "identification_incomplete", identification_coverage: "midstream/no-SYN", binding: "none", mismatch: false, expected: ["", ""], service_port: 1502, outside_rule_port_scope: "unknown", syn_coverage: [false, false] } },
            ] },
        }
      : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json: body });
  });
}

async function screenshot(page: Page, name: string) {
  const dir = process.env.IDENTIFY_SCREENSHOTS;
  if (!dir) return;
  await mkdir(dir, { recursive: true });
  await page.screenshot({ path: `${dir}/${name}.png`, fullPage: true });
}

test.beforeEach(async ({ page }) => { await mockAPI(page); });

test("flows distinguish content from port, mismatch and outside rule ports", async ({ page }) => {
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/flows");
  await page.goto("/flows/");
  await loaded;
  await expect(page.getByText("modbus · content", { exact: true })).toBeVisible();
  await expect(page.getByText("dnp3 · port", { exact: true })).toBeVisible();
  await expect(page.getByText("Mismatch", { exact: true })).toBeVisible();
  await expect(page.getByText("Outside rule ports", { exact: true })).toBeVisible();
  await screenshot(page, "flows");
});

test("events label identifications and observation-only output", async ({ page }) => {
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/events");
  await page.goto("/events/");
  await loaded;
  await expect(page.getByText("Content identification", { exact: true })).toBeVisible();
  await expect(page.getByText("modbus · content", { exact: true })).toBeVisible();
  await expect(page.getByText("Observation only", { exact: true })).toBeVisible();
  await screenshot(page, "events");
});

test("PCAP shows identity, coverage, binding, endpoints and unknown scope", async ({ page }) => {
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/pcap/list");
  await page.goto("/pcap/");
  await loaded;
  const analyzed = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/pcap/analyze/alternate.pcap");
  await page.getByRole("row").filter({ hasText: "alternate.pcap" }).getByRole("button", { name: "Analyze", exact: true }).click();
  await analyzed;
  const section = page.getByRole("region", { name: "Content identifications (2)", exact: true });
  await expect(section).toBeVisible();
  await expect(section.getByText("modbus · content", { exact: true })).toBeVisible();
  const connection = section.getByRole("cell", { name: "10.0.0.1:49152 → 10.0.0.2:20000", exact: true });
  await expect(connection).toBeVisible();
  await expect(connection).toHaveAttribute("title", `capture/1\n${flow.flowId}`);
  await expect(section.getByRole("cell", { name: "[2001:db8::1]:49153 → [2001:db8::2]:1502", exact: true })).toBeVisible();
  await expect(section.getByText(flow.flowId, { exact: true })).toHaveCount(0);
  for (const text of ["observation", "none / dnp3", "tcp/20000", "midstream/no-SYN", "Unknown (no snapshot)"])
    await expect(section.getByText(text, { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("cell", { name: "identify", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /Stage .*Rule/ })).toHaveCount(0);
  await expect(page.getByText("The capture is incomplete. Missing events or identifications may be due to truncated records.")).toHaveCount(0);
  await screenshot(page, "pcap");
});

test("PCAP warns when analysis reports truncated coverage", async ({ page }) => {
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/pcap/list");
  await page.goto("/pcap/?truncated=true");
  await loaded;
  const analyzed = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/pcap/analyze/alternate.pcap");
  await page.getByRole("row").filter({ hasText: "alternate.pcap" }).getByRole("button", { name: "Analyze", exact: true }).click();
  await analyzed;
  const warning = page.getByRole("status").getByText("The capture is incomplete. Missing events or identifications may be due to truncated records.");
  await expect(warning).toBeVisible();
  const dir = process.env.IDENTIFY_SCREENSHOTS;
  if (dir) {
    await mkdir(dir, { recursive: true });
    await page.screenshot({ path: `${dir}/pcap-truncated.png`, fullPage: true });
  }
});
