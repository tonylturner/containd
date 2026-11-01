import { expect, test, type Page } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import type { FirewallRule } from "../lib/api";

// Headless page tests for the IEC 104 UI against a mocked management API.

const adminUser = { id: "admin-1", username: "containd", role: "admin" };

const iecRules = [
  {
    id: "cc-rtu-breaker-command",
    sourceZones: ["lan4"],
    destZones: ["lan1"],
    protocols: [{ name: "tcp", port: "2404" }],
    ics: {
      protocol: "iec104",
      typeIds: [46],
      classes: ["control"],
      direction: "request",
      ca: [1],
      ioa: [{ start: 2001, end: 2001 }],
      commandStates: [1],
      commandQualifiers: [0],
      mode: "enforce",
    },
    action: "ALLOW",
    log: true,
  },
];

const session = "0123456789abcdef0123456789abcdef-1f";

const evidenceEvents = [
  {
    id: "3",
    flowId: "flow-a",
    proto: "iec104",
    kind: "ics.session",
    attributes: { session_id: session, outcome: "reset_sent", target: "client" },
    timestamp: "2026-11-07T09:15:03Z",
    srcIp: "10.60.60.10",
    dstIp: "10.30.30.30",
    srcPort: 40001,
    dstPort: 2404,
    transport: "tcp",
  },
  {
    id: "2",
    flowId: "flow-a",
    proto: "iec104",
    kind: "ics.verdict",
    attributes: {
      session_id: session,
      outcome: "dropped",
      apdu_ids: [`${session}/c/16`],
      trigger_apdu_id: `${session}/c/16`,
    },
    timestamp: "2026-11-07T09:15:02Z",
    srcIp: "10.60.60.10",
    dstIp: "10.30.30.30",
    srcPort: 40001,
    dstPort: 2404,
    transport: "tcp",
  },
  {
    id: "1",
    flowId: "flow-a",
    proto: "iec104",
    kind: "ics.decision",
    attributes: {
      session_id: session,
      decision: "deny",
      ruleId: "deny-other-iec104",
      action: "DENY",
      mode: "enforce",
      reason: "rule",
      apdu_id: `${session}/c/16`,
      type_id: 45,
      ca: 1,
      ioa: 2002,
      direction: "request",
    },
    timestamp: "2026-11-07T09:15:02Z",
    srcIp: "10.60.60.10",
    dstIp: "10.30.30.30",
    srcPort: 40001,
    dstPort: 2404,
    transport: "tcp",
  },
];

// Two incarnations on the same tuple share a flowId and must stay separate.
const flows = [
  {
    flowId: "flow-a",
    session_id: session,
    firstSeen: "2026-11-07T09:15:00Z",
    lastSeen: "2026-11-07T09:15:03Z",
    srcIp: "10.60.60.10",
    dstIp: "10.30.30.30",
    srcPort: 40001,
    dstPort: 2404,
    transport: "tcp",
    application: "iec104",
    eventCount: 3,
  },
  {
    flowId: "flow-a",
    session_id: "0123456789abcdef0123456789abcdef-20",
    firstSeen: "2026-11-07T09:15:04Z",
    lastSeen: "2026-11-07T09:15:05Z",
    srcIp: "10.60.60.10",
    dstIp: "10.30.30.30",
    srcPort: 40001,
    dstPort: 2404,
    transport: "tcp",
    application: "iec104",
    eventCount: 2,
  },
];

const dataplane = {
  captureInterfaces: ["wan"],
  dpiEnabled: true,
  dpiMode: "enforce",
  dpiProtocols: {},
  dpiIcsProtocols: { modbus: true },
  nfqueueGroup: 101,
};

function body(pathname: string): unknown {
  switch (pathname) {
    case "/api/v1/auth/me":
    case "/api/v1/auth/session":
      return adminUser;
    case "/api/v1/firewall/rules":
      return iecRules;
    case "/api/v1/dataplane":
      return dataplane;
    case "/api/v1/health":
      return {
        status: "ok",
        component: "mgmt",
        iec104Enforcement: { active: true, healthy: false, reason: "queue bind failed" },
      };
    case "/api/v1/events":
      return evidenceEvents;
    case "/api/v1/flows":
      return flows;
    case "/api/v1/zones":
    case "/api/v1/conntrack":
      return [];
    case "/api/v1/firewall/nat":
      return { enabled: false };
    case "/api/v1/routing":
      return { gateways: [], routes: [], rules: [] };
    default:
      return {};
  }
}

async function mockAPI(
  page: Page,
  writes: Array<{ method: string; path: string; body: unknown }>,
  writeError?: string,
) {
  const rules = structuredClone(iecRules) as FirewallRule[];
  await page.route("**/api/v1/**", async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    if (req.method() !== "GET") {
      writes.push({ method: req.method(), path: url.pathname, body: req.postDataJSON() });
      if (!writeError && req.method() === "PATCH" && url.pathname.endsWith("/cc-rtu-breaker-command")) {
        rules[0].ics = Object.fromEntries(
          Object.entries({ ...rules[0].ics, ...req.postDataJSON().ics }).filter(([, value]) => value != null),
        );
      }
      await route.fulfill(
        writeError
          ? { status: 400, contentType: "application/json", body: JSON.stringify({ error: writeError }), headers: { "X-Containd-Revision": "0123456789abcdef.1" } }
          : { status: 200, contentType: "application/json", body: JSON.stringify(req.postDataJSON()), headers: { "X-Containd-Revision": "0123456789abcdef.1" } },
      );
      return;
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(url.pathname === "/api/v1/firewall/rules" ? rules : url.pathname === "/api/v1/events" && url.searchParams.has("query") ? { events: evidenceEvents, historyTruncated: true } : body(url.pathname)), headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
}

function trackErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") errors.push(msg.text());
  });
  page.on("pageerror", (err) => errors.push(String(err)));
  return errors;
}

test("ICS page shows IEC rules, amber health with reason, and saves the wire shape", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1200 });
  const writes: Array<{ method: string; path: string; body: unknown }> = [];
  await mockAPI(page, writes);
  const errors = trackErrors(page);
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/firewall/rules");
  await page.goto("/ics");
  await loaded;
  await expect(page.getByText("IEC 104 enforcement unhealthy").first()).toBeVisible();
  await expect(page.getByText("queue bind failed").first()).toBeVisible();
  await expect(page.getByText("type 46 control request state DCS 1 (off) QU 0")).toBeVisible();
  await expect(page.getByText("CA 1 IOA 2001")).toBeVisible();

  await page.getByRole("button", { name: "Edit" }).click();
  await page.getByText("Advanced selectors (saved values still apply)", { exact: true }).click();
  await expect(page.getByText("Write-only", { exact: true })).toHaveCount(0);
  await expect(page.getByPlaceholder("3, 16")).toHaveCount(0);
  await expect(page.getByPlaceholder("2001, 65536-65567")).toHaveValue("2001");
  await page.getByPlaceholder("1", { exact: true }).fill("1, 2");
  await expect(page.getByLabel("Command states", { exact: true })).toHaveValue("1");
  await expect(page.getByLabel("Command qualifiers (QU)", { exact: true })).toHaveValue("0");
  await expect(page.getByText("DCS 1 (off), 2 (on)", { exact: true })).toBeVisible();
  await page.getByLabel("Command states", { exact: true }).fill("2");
  await page.getByLabel("Command qualifiers (QU)", { exact: true }).fill("31");
  const dir = process.env.IEC_PRED_SCREENSHOTS;
  if (dir) {
    await mkdir(dir, { recursive: true });
    await page.screenshot({ path: `${dir}/iec104-editor.png`, fullPage: true, animations: "disabled", style: "nextjs-portal { display: none !important; }" });
  }
  await page.getByRole("button", { name: "Save filter" }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0].method).toBe("PATCH");
  expect(writes[0].path).toBe("/api/v1/firewall/rules/cc-rtu-breaker-command");
  expect(writes[0].body).toEqual({
    ics: {
      protocol: "iec104",
      typeIds: [46],
      classes: ["control"],
      direction: "request",
      ca: [1, 2],
      ioa: [{ start: 2001, end: 2001 }],
      commandStates: [2],
      commandQualifiers: [31],
      readOnly: false,
      mode: "enforce",
    },
  });
  await page.getByRole("button", { name: "Edit" }).click();
  await page.getByText("Advanced selectors (saved values still apply)", { exact: true }).click();
  await expect(page.getByLabel("Command states", { exact: true })).toHaveValue("2");
  await expect(page.getByLabel("Command qualifiers (QU)", { exact: true })).toHaveValue("31");
  await page.getByLabel("Command states", { exact: true }).fill("");
  await page.getByLabel("Command qualifiers (QU)", { exact: true }).fill("");
  await page.getByRole("button", { name: "Save filter" }).click();
  await expect.poll(() => writes.length).toBe(2);
  expect(writes[1].body).toMatchObject({ ics: { commandStates: null, commandQualifiers: null } });
  await page.getByRole("button", { name: "Edit" }).click();
  await page.getByText("Advanced selectors (saved values still apply)", { exact: true }).click();
  await expect(page.getByLabel("Command states", { exact: true })).toHaveValue("");
  await expect(page.getByLabel("Command qualifiers (QU)", { exact: true })).toHaveValue("");
  expect(errors).toEqual([]);
});

test("IEC editor rejects command predicate domains before saving and explains state meanings", async ({ page }) => {
  const writes: Array<{ method: string; path: string; body: unknown }> = [];
  await mockAPI(page, writes);
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/firewall/rules");
  await page.goto("/ics");
  await loaded;
  await page.getByRole("button", { name: "Edit" }).click();
  await page.getByText("Advanced selectors (saved values still apply)", { exact: true }).click();
  for (const [types, state, qualifier, error] of [
    ["", "1", "0", "require explicit Type IDs"],
    ["48", "", "0", "require explicit Type IDs"],
    ["45, 46", "1", "0", "cannot mix SCS"],
    ["45", "2", "0", "must be in 0-1"],
    ["46", "0", "0", "must be in 1-2"],
    ["46", "1", "32", "integer from 0 to 31"],
    ["46", "1.5", "0", "integer from 0 to 2"],
  ]) {
    await page.getByPlaceholder("46, 100").fill(types);
    await page.getByLabel("Command states", { exact: true }).fill(state);
    await page.getByLabel("Command qualifiers (QU)", { exact: true }).fill(qualifier);
    await page.getByRole("button", { name: "Save filter" }).click();
    await expect(page.locator("p.text-red-400").filter({ hasText: error })).toBeVisible();
    expect(writes).toEqual([]);
  }
  for (const [types, help] of [["45, 58", "SCS 0 (off), 1 (on)"], ["47, 60", "RCS 1 (lower), 2 (higher)"]]) {
    await page.getByPlaceholder("46, 100").fill(types);
    await expect(page.getByText(help, { exact: true })).toBeVisible();
  }
});

test("client navigation keeps verified page content visible while revalidating the session", async ({ page }) => {
  let authRequests = 0;
  let holdAuthAfter = Number.POSITIVE_INFINITY;
  let releaseHeldAuth: () => void = () => {};
  let notifyHeldAuth: () => void = () => {};
  const heldAuth = new Promise<void>((resolve) => {
    notifyHeldAuth = resolve;
  });
  const heldResponse = new Promise<void>((resolve) => {
    releaseHeldAuth = resolve;
  });

  await page.route("**/api/v1/**", async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    if (req.method() === "GET" && url.pathname === "/api/v1/auth/me") {
      authRequests += 1;
      if (authRequests > holdAuthAfter) {
        notifyHeldAuth();
        await heldResponse;
      }
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(url.pathname === "/api/v1/events" && url.searchParams.has("query") ? { events: evidenceEvents, historyTruncated: true } : body(url.pathname)), headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });

  try {
    await page.goto("/ics");
    await expect(page.getByText("queue bind failed").first()).toBeVisible();
    holdAuthAfter = authRequests;

    await page.getByRole("button", { name: "Monitoring" }).click();
    await page.getByRole("link", { name: "Events" }).click();
    await page.waitForURL("**/events/");
    await heldAuth;

    await expect(
      page
        .getByRole("main", { name: "Events" })
        .getByText(/Use Events for activity records and service activity/),
    ).toBeVisible();
    await expect(page.getByText("Checking session...")).toHaveCount(0);
  } finally {
    releaseHeldAuth();
  }
});

test("ICS editor refuses a broadcast CA before saving", async ({ page }) => {
  const writes: Array<{ method: string; path: string; body: unknown }> = [];
  await mockAPI(page, writes);
  await page.goto("/ics");
  await page.getByRole("button", { name: "Edit" }).click();
  await page.getByText("Advanced selectors (saved values still apply)", { exact: true }).click();
  await page.getByPlaceholder("1", { exact: true }).fill("65535");
  await page.getByRole("button", { name: "Save filter" }).click();
  await expect(page.getByText("CA 65535 is the broadcast address")).toBeVisible();
  expect(writes).toEqual([]);
});

test("Events shows decision, verdict and reset evidence and filters by session", async ({ page }) => {
  await mockAPI(page, []);
  const errors = trackErrors(page);
  const request = page.waitForRequest((req) => {
    const url = new URL(req.url());
    return url.pathname === "/api/v1/events" && url.searchParams.get("session") === session && url.searchParams.get("category") === "iec104";
  });
  await page.goto(`/events?filter=iec104&session=${session}`);
  await request;
  await expect(page.getByText(/history may have gaps/)).toBeVisible();
  await expect(page.getByText("IEC 104 APDU denied")).toBeVisible();
  await expect(page.getByText("IEC 104 packets dropped")).toBeVisible();
  await expect(page.getByText("IEC 104 reset sent to client")).toBeVisible();
  await expect(page.getByText(`Session ${session} ×`)).toBeVisible();
  const message = page.locator("details").filter({ has: page.getByText("Message and session details", { exact: true }) }).first();
  await message.locator("summary").click();
  await expect(message.getByText(session, { exact: true })).toBeVisible();
  const attributes = page.locator("details").filter({ has: page.getByText("Event attributes (JSON)", { exact: true }) }).first();
  await expect(attributes.locator("pre")).not.toBeVisible();
  await attributes.locator("summary").click();
  await expect(attributes.locator("pre")).toBeVisible();
  await expect(attributes.locator("pre")).toContainText(session);
  expect(errors).toEqual([]);
});

test("Alerts lists IEC 104 evidence with a detail panel", async ({ page }) => {
  await mockAPI(page, []);
  const errors = trackErrors(page);
  await page.goto("/alerts");
  await expect(page.getByText("deny: type 45 CA 1 IOA 2002 (matched rule, deny-other-iec104)")).toBeVisible();
  await page.getByText("Dropped 1 APDU of an aborted session").click();
  await expect(page.getByText("IEC 104 Evidence", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "IEC 104 packets dropped", exact: true })).toBeVisible();
  await expect(page.getByText("Dropped APDUs", { exact: true }).locator("..").getByText(`${session}/c/16`, { exact: true })).toBeVisible();
  const sessionLink = page.getByRole("link", { name: /Open session events/ });
  await expect(sessionLink).toBeVisible();
  await expect(sessionLink).toHaveAttribute("href", `/events/?filter=iec104&session=${session}`);
  expect(errors).toEqual([]);
});

test("Flows shows each IEC session incarnation by session_id", async ({ page }) => {
  await mockAPI(page, []);
  const errors = trackErrors(page);
  await page.goto("/flows");
  await expect(page.getByText("IEC 104 sessions: 2")).toBeVisible();
  await expect(page.getByText("IEC 012345…-1f")).toBeVisible();
  await expect(page.getByText("IEC 012345…-20")).toBeVisible();
  const evidenceRequest = page.waitForRequest((req) => new URL(req.url()).searchParams.get("session") === session);
  await page.getByRole("link", { name: "Evidence", exact: true }).first().click();
  await evidenceRequest;
  await expect(page.getByText("IEC 104 APDU denied")).toBeVisible();
  expect(errors).toEqual([]);
});

test("Firewall DPI section lists the IEC 104 decoder as enabled when unset", async ({ page }) => {
  await mockAPI(page, []);
  const errors = trackErrors(page);
  await page.goto("/firewall");
  const decoders = page.getByText("Industrial protocols").locator("xpath=../../..");
  await expect(decoders.getByText("4/4 enabled")).toBeVisible();
  await expect(decoders.getByText("IEC 60870-5-104", { exact: true })).toBeVisible();
  expect(errors).toEqual([]);
});

for (const command of [false, true]) {
  test(`Firewall create form sends only IEC keys for an iec104 ${command ? "command" : "system"} rule`, async ({ page }) => {
    const writes: Array<{ method: string; path: string; body: unknown }> = [];
    await mockAPI(page, writes);
    await page.goto("/firewall");
    await page.getByPlaceholder("id (e.g. mb-allow)").fill(command ? "cc-rtu-command" : "cc-rtu-gi");
    await page.getByRole("checkbox", { name: /ICS Protocol Filter/ }).check();
    await page.locator("select").filter({ has: page.locator('option[value="iec104"]') }).selectOption("iec104");
    await expect(page.getByPlaceholder("0x02, 0x04, 0x66")).toHaveCount(0);
    await page.getByPlaceholder("46, 100").fill(command ? "45" : "100");
    await page.getByRole("button", { name: command ? "control" : "system", exact: true }).click();
    if (command) {
      await page.getByText("Advanced selectors (saved values still apply)", { exact: true }).click();
      await page.getByLabel("Command states", { exact: true }).fill("0");
      await page.getByLabel("Command qualifiers (QU)", { exact: true }).fill("0");
    }
    await page.getByRole("button", { name: "Create rule" }).click();
    await expect.poll(() => writes.length).toBe(1);
    expect(writes[0].method).toBe("POST");
    expect((writes[0].body as { ics: unknown }).ics).toEqual({
      protocol: "iec104",
      typeIds: [command ? 45 : 100],
      classes: [command ? "control" : "system"],
      ...(command ? { commandStates: [0], commandQualifiers: [0] } : {}),
      readOnly: false,
    });
  });
}

test("Turning the IEC 104 decoder off saves an explicit false", async ({ page }) => {
  const writes: Array<{ method: string; path: string; body: unknown }> = [];
  await mockAPI(page, writes);
  await page.goto("/firewall");
  const decoders = page.getByText("Industrial protocols").locator("xpath=../../..");
  await decoders.getByRole("button", { name: "Configure" }).click();
  await page.getByRole("switch", { name: "Inspect IEC 60870-5-104" }).click();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0].path).toBe("/api/v1/dataplane");
  expect((writes[0].body as { dpiIcsProtocols: unknown }).dpiIcsProtocols).toEqual({
    modbus: true,
    iec104: false,
  });
  expect((writes[0].body as { nfqueueGroup: unknown }).nfqueueGroup).toBe(101);
});

test("A rejected decoder change is reverted and its reason shown", async ({ page }) => {
  const writes: Array<{ method: string; path: string; body: unknown }> = [];
  const reason = "iec104 enforce requires the iec104 decoder";
  await mockAPI(page, writes, reason);
  await page.goto("/firewall");
  const decoders = page.getByText("Industrial protocols").locator("xpath=../../..");
  await decoders.getByRole("button", { name: "Configure" }).click();
  await page.getByRole("switch", { name: "Inspect IEC 60870-5-104" }).click();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText(`Not saved: ${reason}`)).toBeVisible();
  await expect(decoders.getByText("4/4 enabled")).toBeVisible();
});

test("Events sends edited filters before limiting and loads older evidence with cursor", async ({ page }) => {
  await mockAPI(page, []);
  const requests: URL[] = [];
  await page.route("**/api/v1/events?**", async (route) => {
    const url = new URL(route.request().url()); requests.push(url);
    if (url.searchParams.get("session") === "unavailable") { await route.fulfill({ status: 503, json: { error: "offline" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }); return; }
    const older = url.searchParams.get("cursor") === "older";
    await route.fulfill({ json: { events: older ? [evidenceEvents[2]] : [evidenceEvents[0]], nextCursor: older ? undefined : "older", historyTruncated: true }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  await page.goto(`/events?flow=flow-a&protocol=iec104&decision=deny&since=2026-01-01T00:00:00Z`);
  await expect(page.getByText("IEC 104 reset sent to client")).toBeVisible();
  expect(requests[0].searchParams.get("flow")).toBe("flow-a");
  expect(requests[0].searchParams.get("decision")).toBe("deny");
  expect(requests[0].searchParams.get("since")).toBe("2026-01-01T00:00:00Z");
  await page.getByLabel("Verdict / outcome").fill("drop_failed");
  await expect.poll(() => requests[requests.length - 1]?.searchParams.get("verdict")).toBe("drop_failed");
  await page.getByRole("button", { name: "Live", exact: true }).click();
  await page.getByRole("button", { name: "Load older evidence", exact: true }).click();
  await expect(page.getByText("IEC 104 APDU denied")).toBeVisible();
  await expect(page.getByText("IEC 104 reset sent to client")).toBeVisible();
  expect(requests[requests.length - 1]?.searchParams.get("cursor")).toBe("older");
  expect(requests[requests.length - 1]?.searchParams.get("verdict")).toBe("drop_failed");
  await page.getByLabel("Session ID", { exact: true }).fill("unavailable");
  await expect(page.getByText("Traffic records unavailable. Check filters and retry with Refresh.")).toBeVisible();
  await page.getByText("Technical details", { exact: true }).click();
  await expect(page.getByText(/Failed to load events/)).toBeVisible();
  await expect(page.getByText("IEC 104 APDU denied")).not.toBeVisible();
  await expect(page.getByText("IEC 104 reset sent to client")).not.toBeVisible();
});
