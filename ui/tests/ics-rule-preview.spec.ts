import { expect, test, type Page, type Request } from "@playwright/test";

// The ICS filter editor previews the whole rule with the edited predicate
// through the authenticated API client, using the preview's wire shape.

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };
const sessionToken = "session-token-1";
const rule = {
  id: "plc-read",
  action: "ALLOW",
  sourceZones: ["it"],
  destZones: ["ot"],
  protocols: [{ name: "tcp", port: "502" }],
  identities: ["historian"],
  schedule: { daysOfWeek: ["Saturday"], startTime: "02:00", endTime: "06:00" },
  ics: { protocol: "modbus", functionCode: [3], readOnly: true, mode: "enforce" },
};
const warning = {
  ruleId: "plc-read",
  predicate: "identity",
  action: "ALLOW",
  message: "no bound address can match identities [historian]; the rule matches nothing until one is bound",
};
const preview = {
  match_count: 1234,
  sample_matches: [
    {
      id: 41,
      flowId: "flow-1",
      proto: "modbus",
      kind: "request",
      attributes: { function_code: 3 },
      timestamp: "2026-10-26T09:15:02Z",
      srcIp: "10.10.0.5",
      dstIp: "10.20.0.7",
      srcPort: 40100,
      dstPort: 502,
      transport: "tcp",
    },
  ],
  time_range: { start: "2026-10-26T08:00:00Z", end: "2026-10-26T09:15:02Z" },
  total_events: 5000,
  warnings: [warning],
};

type PreviewReply = { status: number; json: unknown };

async function openICS(page: Page, reply: PreviewReply, previews: Request[]) {
  await page.addInitScript((token) => {
    localStorage.setItem("containd.auth.role", "admin");
    sessionStorage.setItem("containd.session.token", token);
  }, sessionToken);
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/firewall/rules/preview") {
      previews.push(request);
      // Only the session token authenticates this route.
      if (request.headers()["authorization"] !== `Bearer ${sessionToken}`) {
        await route.fulfill({ status: 401, json: { error: "unauthorized" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
        return;
      }
      await route.fulfill(reply);
      return;
    }
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/firewall/rules") body = [rule];
    if (path === "/api/v1/dataplane") body = { captureInterfaces: [], dpiMock: false, dpiMode: "enforce" };
    if (path === "/api/v1/health") body = { status: "ok", component: "mgmt" };
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/firewall/rules");
  await page.goto("/ics/");
  await loaded;
  await page.getByRole("button", { name: "Edit", exact: true }).click();
}

function trackErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("pageerror", (err) => errors.push(String(err)));
  return errors;
}

test("ICS rule preview shows the impact and predicate warnings of the edited rule", async ({ page }) => {
  const previews: Request[] = [];
  const errors = trackErrors(page);
  await openICS(page, { status: 200, json: preview }, previews);

  await page.getByPlaceholder("3, 16").fill("3, 4");
  await page.getByRole("button", { name: "Preview impact" }).click();

  const summary = page.getByLabel("Rule impact preview");
  await expect(summary).toContainText("1234 of 5000 recent events match this rule on its own.");
  await summary.getByText("Show 1 sample event").click();
  await expect(summary.getByRole("list", { name: "Sample matching events" })).toContainText("10.10.0.5:40100 → 10.20.0.7:502 (tcp)");
  await expect(summary.getByRole("status")).toContainText(`plc-read: ${warning.message}`);

  // The unauthenticated attempt is retried with the session token.
  expect(previews).toHaveLength(2);
  expect(previews[1].headers()["authorization"]).toBe(`Bearer ${sessionToken}`);
  // The preview keeps the zones, identities and schedule the editor does not change.
  expect(previews[1].postDataJSON()).toMatchObject({
    id: "plc-read",
    action: "ALLOW",
    sourceZones: ["it"],
    destZones: ["ot"],
    identities: rule.identities,
    schedule: rule.schedule,
    ics: { protocol: "modbus", functionCode: [3, 4], readOnly: true, mode: "enforce" },
  });
  expect(errors).toEqual([]);
});

test("ICS rule preview reports an engine without preview support", async ({ page }) => {
  const previews: Request[] = [];
  const errors = trackErrors(page);
  await openICS(page, { status: 503, json: { error: "engine rule preview unavailable" } }, previews);

  await page.getByRole("button", { name: "Preview impact" }).click();

  await expect(page.getByText("Impact preview failed: engine rule preview unavailable")).toBeVisible();
  await expect(page.getByLabel("Rule impact preview")).toHaveCount(0);
  expect(errors).toEqual([]);
});
