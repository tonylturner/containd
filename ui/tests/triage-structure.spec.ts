import { expect, test, type Page } from "@playwright/test";
import type { TelemetryEvent } from "../lib/api";

const session = "0123456789abcdef0123456789abcdef-1";
const base = {
  flowId: "flow-1", timestamp: "2026-11-01T10:00:00Z",
  srcIp: "192.0.2.1", dstIp: "192.0.2.2", srcPort: 41000, dstPort: 2404, transport: "tcp",
};
const events: TelemetryEvent[] = [
  { ...base, id: "1", proto: "ids", kind: "alert", attributes: { message: "Controller command detected", severity: "high" } },
  { ...base, id: "2", proto: "iec104", kind: "ics.decision", attributes: {
    session_id: session, apdu_id: `${session}/c/1`, decision: "would_drop", action: "DENY",
    mode: "monitor", reason: "future-reason", ruleId: "rule-1", future_key: "inspectable",
  } },
  { ...base, id: "3", proto: "iec104", kind: "ics.verdict", attributes: {
    session_id: session, outcome: "dropped", apdu_ids: [`${session}/c/1`],
  } },
  { ...base, id: "4", proto: "iec104", kind: "ics.session", attributes: {
    session_id: session, outcome: "reset_failed", target: "client", error: "reset transport failed",
  } },
  { ...base, id: "5", proto: "iec104", kind: "ics.decision", attributes: {
    session_id: session, apdu_id: `${session}/c/2`, decision: "deny", action: "DENY",
    mode: "enforce", reason: "rule", ruleId: "rule-1",
  } },
];

async function serve(page: Page) {
  const queries: URL[] = [];
  await page.route("**/api/v1/**", async route => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    if (path === "/api/v1/events") queries.push(url);
    const json = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin", username: "containd", role: "admin" }
      : path === "/api/v1/flows" ? [{ ...base, flowId: "flow-1", session_id: session, firstSeen: base.timestamp, lastSeen: base.timestamp, eventCount: 1, tags: ["triage"] }]
        : path === "/api/v1/conntrack" ? [{ proto: "tcp", src: base.srcIp, dst: base.dstIp, sport: "41000", dport: "2404", tags: ["triage"], mark: "1", assured: true, timeoutSecs: 45, replySrc: base.dstIp, replyDst: base.srcIp }]
        : path === "/api/v1/events"
        ? url.searchParams.has("query") ? { events, historyTruncated: true } : events
        : path.startsWith("/api/v1/events/") ? events.find(event => path.endsWith(`/${event.id}`))
          : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  return queries;
}

for (const destination of [
  { name: "Sessions — inspect kernel connections and revoke immediately", path: "/sessions/", query: "" },
  { name: "Open AV events", path: "/events/", query: "?av=1" },
  { name: "Evidence", path: "/events/", query: `?filter=iec104&session=${session}` },
]) {
  test(`flow link uses client navigation and preserves its destination: ${destination.name}`, async ({ page }) => {
    await serve(page);
    const loaded = page.waitForResponse(r => new URL(r.url()).pathname === "/api/v1/flows");
    await page.goto("/flows/");
    await loaded;
    const link = page.getByRole("link", { name: destination.name, exact: true });
    await expect(link).toHaveAttribute("href", `${destination.path}${destination.query}`);
    await page.evaluate(() => Reflect.set(window, "flowNavigationMarker", "same-document"));
    await link.click();
    await expect(page).toHaveURL(new URL(`${destination.path}${destination.query}`, page.url()).href);
    expect(await page.evaluate(() => Reflect.get(window, "flowNavigationMarker"))).toBe("same-document");
  });
}

test("all event deep-link filters survive disclosure and keyboard inspection", async ({ page }) => {
  const queries = await serve(page);
  const params = {
    filter: "iec104", kind: "ics.", av: "1", session, flow: "flow-1", ruleId: "rule-1",
    mode: "monitor", apdu: `${session}/c/1`, protocol: "iec104", decision: "would_drop",
    verdict: "dropped", since: "2026-11-01T00:00:00Z", cursor: "older-exact-id",
  };
  const loaded = page.waitForResponse(r => new URL(r.url()).pathname === "/api/v1/events");
  await page.goto(`/events/?${new URLSearchParams(params)}`);
  await loaded;
  const query = queries.at(-1)!;
  for (const [key, value] of Object.entries(params)) {
    expect(query.searchParams.get(key === "filter" ? "category" : key === "av" ? "detections" : key)).toBe(value);
  }
  const advanced = page.getByRole("button", { name: "Advanced event filters" });
  await expect(advanced).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByLabel("Cursor", { exact: true })).toHaveValue(params.cursor);
  await expect(page.getByText(/history may have gaps/)).toBeVisible();
  await expect(page.getByText(/reset transport failed/).first()).toBeVisible();
  const inspect = page.getByRole("button", { name: "Inspect event", exact: true }).nth(1);
  await expect(inspect).toHaveAttribute("aria-expanded", "false");
  await inspect.focus();
  await page.keyboard.press("Enter");
  await expect(inspect).toBeFocused();
  await expect(inspect).toHaveAttribute("aria-expanded", "true");
  const detail = page.locator("#event-inspection-2");
  await detail.getByText("Message and session details", { exact: true }).click();
  await expect(detail.getByText("future-reason", { exact: true })).toBeVisible();
  await detail.getByText("Event attributes (JSON)", { exact: true }).click();
  await expect(detail.locator("pre")).toContainText('"future_key": "inspectable"');
  await inspect.focus();
  await page.keyboard.press("Space");
  await expect(detail).toBeHidden();
  await expect(inspect).toBeFocused();
  expect(queries.at(-1)!.searchParams.get("cursor")).toBe(params.cursor);
});

test("alerts separate detection, would-block, blocked, reset failure and a deny decision", async ({ page }) => {
  await serve(page);
  await page.goto("/alerts/");
  for (const outcome of [
    "Detection — blocking not reported", "Would-block (monitor)", "Blocked — packet drop reported",
    "Reset failed — closure not confirmed", "Deny decision — packet outcome not reported",
  ]) {
    await expect(page.getByRole("cell", { name: outcome, exact: true })).toBeVisible();
  }
  const inspect = page.getByRole("button", { name: "Controller command detected", exact: true });
  await inspect.focus();
  await page.keyboard.press("Enter");
  await expect(inspect).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByRole("heading", { name: "Controller command detected", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Close", exact: true }).click();
  await expect(inspect).toBeFocused();
  await expect(inspect).toHaveAttribute("aria-expanded", "false");
});

test("triage table and inspector stay inside a 390px viewport", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await serve(page);
  await page.goto("/alerts/");
  await page.getByRole("button", { name: "Controller command detected", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Controller command detected", exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  const table = page.locator("table").locator("..");
  expect(await table.evaluate(element => element.scrollWidth)).toBeGreaterThan(await table.evaluate(element => element.clientWidth));
});


for (const [path, button] of [["/events/", "Inspect event"], ["/flows/", "Inspect flow"], ["/sessions/", "Inspect connection"]]) {
  test(`${path} expands by keyboard without widening a 390px viewport`, async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await serve(page);
    await page.goto(path);
    const inspect = page.getByRole("button", { name: button, exact: true }).first();
    await inspect.focus();
    await page.keyboard.press("Enter");
    await expect(inspect).toHaveAttribute("aria-expanded", "true");
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
    await page.keyboard.press("Space");
    await expect(inspect).toHaveAttribute("aria-expanded", "false");
    await expect(inspect).toBeFocused();
  });
}
