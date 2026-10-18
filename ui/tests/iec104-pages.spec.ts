import { expect, test, type Page } from "@playwright/test";

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
      mode: "enforce",
    },
    action: "ALLOW",
    log: true,
  },
];

const session = "0123456789abcdef0123456789abcdef-1f";

const evidenceEvents = [
  {
    id: 3,
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
    id: 2,
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
    id: 1,
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
  await page.route("**/api/v1/**", async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    if (req.method() !== "GET") {
      writes.push({ method: req.method(), path: url.pathname, body: req.postDataJSON() });
      await route.fulfill(
        writeError
          ? { status: 400, contentType: "application/json", body: JSON.stringify({ error: writeError }) }
          : { status: 200, contentType: "application/json", body: JSON.stringify(req.postDataJSON()) },
      );
      return;
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body(url.pathname)) });
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
  const writes: Array<{ method: string; path: string; body: unknown }> = [];
  await mockAPI(page, writes);
  const errors = trackErrors(page);
  await page.goto("/ics");
  await expect(page.getByText("IEC 104 enforcement unhealthy").first()).toBeVisible();
  await expect(page.getByText("queue bind failed").first()).toBeVisible();
  await expect(page.getByText("type 46 control request")).toBeVisible();
  await expect(page.getByText("CA 1 IOA 2001")).toBeVisible();

  await page.getByRole("button", { name: "Edit" }).click();
  await expect(page.getByText("Write-only", { exact: true })).toHaveCount(0);
  await expect(page.getByPlaceholder("3, 16")).toHaveCount(0);
  await expect(page.getByPlaceholder("2001, 65536-65567")).toHaveValue("2001");
  await page.getByPlaceholder("1", { exact: true }).fill("1, 2");
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
      readOnly: false,
      mode: "enforce",
    },
  });
  expect(errors).toEqual([]);
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
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(body(url.pathname)),
    });
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
        .getByText(/Use Events for raw telemetry and service activity/),
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
  await page.getByPlaceholder("1", { exact: true }).fill("65535");
  await page.getByRole("button", { name: "Save filter" }).click();
  await expect(page.getByText("CA 65535 is the broadcast address")).toBeVisible();
  expect(writes).toEqual([]);
});

test("Events shows decision, verdict and reset evidence and filters by session", async ({ page }) => {
  await mockAPI(page, []);
  const errors = trackErrors(page);
  await page.goto(`/events?filter=iec104&session=${session}`);
  await expect(page.getByText("IEC 104 APDU denied")).toBeVisible();
  await expect(page.getByText("IEC 104 packets dropped")).toBeVisible();
  await expect(page.getByText("IEC 104 reset sent to client")).toBeVisible();
  await expect(page.getByText(`Session ${session} ×`)).toBeVisible();
  expect(errors).toEqual([]);
});

test("Alerts lists IEC 104 evidence with a detail panel", async ({ page }) => {
  await mockAPI(page, []);
  const errors = trackErrors(page);
  await page.goto("/alerts");
  await expect(page.getByText("deny: type 45 CA 1 IOA 2002 (matched rule, deny-other-iec104)")).toBeVisible();
  await page.getByText("Dropped 1 APDU of an aborted session").click();
  await expect(page.getByText("IEC 104 Enforcement")).toBeVisible();
  await expect(page.getByRole("link", { name: /Open session events/ })).toBeVisible();
  expect(errors).toEqual([]);
});

test("Flows shows each IEC session incarnation by session_id", async ({ page }) => {
  await mockAPI(page, []);
  const errors = trackErrors(page);
  await page.goto("/flows");
  await expect(page.getByText("IEC 104 sessions: 2")).toBeVisible();
  await expect(page.getByText("IEC 012345…-1f")).toBeVisible();
  await expect(page.getByText("IEC 012345…-20")).toBeVisible();
  expect(errors).toEqual([]);
});

test("Firewall DPI section lists the IEC 104 decoder as enabled when unset", async ({ page }) => {
  await mockAPI(page, []);
  const errors = trackErrors(page);
  await page.goto("/firewall");
  const decoders = page.getByText("ICS Protocol Decoders").locator("xpath=../../..");
  await expect(decoders.getByText("8/8 enabled")).toBeVisible();
  await expect(decoders.getByText("IEC 60870-5-104", { exact: true })).toBeVisible();
  expect(errors).toEqual([]);
});

test("Firewall create form sends only IEC keys for an iec104 rule", async ({ page }) => {
  const writes: Array<{ method: string; path: string; body: unknown }> = [];
  await mockAPI(page, writes);
  await page.goto("/firewall");
  await page.getByPlaceholder("id (e.g. mb-allow)").fill("cc-rtu-gi");
  await page.getByRole("checkbox", { name: /ICS Protocol Filter/ }).check();
  await page.locator("select").filter({ has: page.locator('option[value="iec104"]') }).selectOption("iec104");
  await expect(page.getByPlaceholder("0x02, 0x04, 0x66")).toHaveCount(0);
  await page.getByPlaceholder("46, 100").fill("100");
  await page.getByRole("button", { name: "system", exact: true }).click();
  await page.getByRole("button", { name: "Create rule" }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0].method).toBe("POST");
  expect((writes[0].body as { ics: unknown }).ics).toEqual({
    protocol: "iec104",
    typeIds: [100],
    classes: ["system"],
    readOnly: false,
    mode: "learn",
  });
});

test("Turning the IEC 104 decoder off saves an explicit false", async ({ page }) => {
  const writes: Array<{ method: string; path: string; body: unknown }> = [];
  await mockAPI(page, writes);
  await page.goto("/firewall");
  const decoders = page.getByText("ICS Protocol Decoders").locator("xpath=../../..");
  await decoders.getByRole("button", { name: "Configure" }).click();
  const row = page.getByText("APCI frames, Type IDs, common addresses, IOAs").locator("xpath=../../..");
  await row.locator("div.rounded-full").click();
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
  const decoders = page.getByText("ICS Protocol Decoders").locator("xpath=../../..");
  await decoders.getByRole("button", { name: "Configure" }).click();
  const row = page.getByText("APCI frames, Type IDs, common addresses, IOAs").locator("xpath=../../..");
  await row.locator("div.rounded-full").click();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText(`Not saved: ${reason}`)).toBeVisible();
  await expect(decoders.getByText("8/8 enabled")).toBeVisible();
});
