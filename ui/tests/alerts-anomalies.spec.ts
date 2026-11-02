import { expect, test, type Page } from "@playwright/test";
import type { TelemetryEvent } from "../lib/api";
import { mockProtection } from "./fixtures/protection-api";

const headline = "IEC 104 send sequence anomaly";
const anomaly: TelemetryEvent = {
  id: "1", flowId: "flow-1", proto: "ids", kind: "anomaly", timestamp: "2026-11-01T12:00:00Z",
  srcIp: "192.0.2.10", dstIp: "192.0.2.20", srcPort: 49152, dstPort: 2404,
  transport: "tcp",
  attributes: {
    protocol: "iec104", anomaly_type: "iec104_send_sequence", severity: "medium",
    session_id: "session-1", direction: "request", send_sequence: 3, expected_send_sequence: 1,
  },
};

async function load(page: Page, role = "admin", alert = anomaly) {
  const state = {
    status: 200, hold: null as Promise<void> | null,
    writes: [] as { path: string; method: string; revision?: string }[],
  };
  await page.addInitScript(role => {
    localStorage.setItem("containd.auth.role", role);
    sessionStorage.setItem("containd.session.token", "test-token");
  }, role);
  await page.route("**/api/v1/**", async route => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (request.method() !== "GET") {
      request.postDataBuffer();
      state.writes.push({ path, method: request.method(), revision: request.headers()["x-containd-if-revision"] });
      if (state.hold) await state.hold;
      return route.fulfill({
        status: state.status,
        json: state.status === 200 ? { status: "ok" } : { error: "anomaly detector unavailable" },
      });
    }
    const json = path.includes("/auth/") ? { id: role, username: role, role }
      : path === "/api/v1/events" ? [alert]
      : path === "/api/v1/config/diff" ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  await mockProtection(page);
  await Promise.all([page.waitForResponse("**/api/v1/events*"), page.goto("/alerts/")]);
  return state;
}

for (const width of [1280, 390]) {
  test(`anomaly clearing is confirmed and immediate, retaining historical alerts at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 960 });
    const state = await load(page);
    await page.getByRole("cell", { name: headline, exact: true }).click();
    const clear = page.getByRole("button", { name: "Clear anomalies (immediate)", exact: true });
    await clear.click();
    const dialog = page.getByRole("dialog", { name: "Clear anomalies?" });
    await expect(dialog).toContainText("all detected protocol anomalies and reset detector tracking state");
    await expect(dialog).toContainText("Historical alert events and configuration remain unchanged");
    await expect(dialog).toContainText("does not require a commit");
    expect(state.writes).toEqual([]);
    await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
    expect(state.writes).toEqual([]);
    await expect(page.getByRole("cell", { name: headline, exact: true })).toBeVisible();
    await clear.click();
    let release!: () => void;
    state.hold = new Promise<void>(resolve => { release = resolve; });
    await dialog.getByRole("button", { name: "Clear anomalies", exact: true }).click();
    await expect.poll(() => state.writes.length).toBe(1);
    await expect(page.getByRole("button", { name: "Clearing anomalies…" })).toBeDisabled();
    await expect(page.getByRole("dialog")).toHaveCount(0);
    release();
    await expect(page.getByRole("status").filter({ hasText: "Anomalies cleared immediately." }))
      .toHaveText("Anomalies cleared immediately. Historical alert events remain. New traffic can create more anomalies.");
    expect(state.writes).toEqual([{ path: "/api/v1/anomalies", method: "DELETE", revision: undefined }]);
    await expect(page.getByRole("cell", { name: headline, exact: true })).toBeVisible();
    await expect(clear).toBeEnabled();
    await clear.scrollIntoViewIfNeeded();
    await expect(clear).toBeInViewport({ ratio: 1 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  });
}

test("anomaly clear failures stay visible and allow an explicit retry", async ({ page }) => {
  const state = await load(page);
  state.status = 503;
  await page.getByRole("cell", { name: headline, exact: true }).click();
  const clear = page.getByRole("button", { name: "Clear anomalies (immediate)", exact: true });
  await clear.click();
  await page.getByRole("dialog").getByRole("button", { name: "Clear anomalies", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "anomaly detector unavailable" })).toBeVisible();
  await expect(page.getByText(/Anomalies cleared immediately/)).toHaveCount(0);
  await expect(page.getByRole("cell", { name: headline, exact: true })).toBeVisible();
  await expect(clear).toBeEnabled();
  expect(state.writes).toHaveLength(1);
  state.status = 200;
  await clear.click();
  await page.getByRole("dialog").getByRole("button", { name: "Clear anomalies", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "anomaly detector unavailable" })).toHaveCount(0);
  await expect(page.getByRole("status").filter({ hasText: "Anomalies cleared immediately." })).toBeVisible();
  expect(state.writes).toHaveLength(2);
});

test("viewers can inspect anomalies but cannot clear them", async ({ page }) => {
  const state = await load(page, "view");
  await page.getByRole("cell", { name: headline, exact: true }).click();
  await expect(page.getByRole("heading", { name: headline, exact: true })).toBeVisible();
  await expect(page.getByText(/Clearing resets all detected anomalies/)).toBeVisible();
  await expect(page.getByRole("button", { name: /Clear anomalies/ })).toHaveCount(0);
  expect(state.writes).toEqual([]);
});

test("an IEC 104 enforcement decision does not offer anomaly clearing", async ({ page }) => {
  const state = await load(page, "admin", {
    ...anomaly, proto: "iec104", kind: "ics.decision",
    attributes: { session_id: "session-1", apdu_id: "session-1/c/1", decision: "deny", reason: "rule", action: "DENY", mode: "enforce", ruleId: "deny-rule", type_id: 46, ca: 1, ioa: 2001, direction: "request" },
  });
  await page.getByRole("cell", { name: /deny: type 46/ }).click();
  await expect(page.getByRole("heading", { name: "IEC 104 APDU denied" })).toBeVisible();
  await expect(page.getByRole("button", { name: /Clear anomalies/ })).toHaveCount(0);
  expect(state.writes).toEqual([]);
});
