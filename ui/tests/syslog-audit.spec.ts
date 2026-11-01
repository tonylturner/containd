import { expect, test, type Page } from "@playwright/test";

// GET /services/status reports audit-record forwarding under syslog.audit:
// totals, the summed backlog and the last error, and per forwarder its
// cursor, backlog, last delivery and last error.

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };
const meter = { sparkline: [], count: 0, rate_per_min: 0, errors_sparkline: [], errors_count: 0, errors_rate_per_min: 0 };
const syslog = {
  ...meter, configured_forwarders: 2, format: "rfc5424", protos: ["udp", "tcp"], sent_total: 40, failed_total: 0,
  last_flush: "2026-10-26T08:00:00Z", last_error: "", last_batch: 4, batch_limit: 500, hit_limit: false, flush_interval_sec: 2,
  events: [
    { destination: "tcp://192.0.2.11:6514", source: "engine", epoch: "run-1", offset: "9223372036854775809",
      backlog: 13, sent: 21, failed: 3, lost: 7, continuity_unknown: 2, last_error: "source offline", last_success: "" },
    { destination: "udp://192.0.2.10:514", source: "services", epoch: "run-2", offset: "4",
      backlog: 0, sent: 4, failed: 0, lost: 0, continuity_unknown: 0, last_error: "", last_success: "" },
  ],
};

async function open(page: Page, audit: unknown) {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = path.endsWith("/auth/me") || path.endsWith("/auth/session") ? user
      : path === "/api/v1/services/status" ? { syslog: { ...syslog, ...(audit === undefined ? {} : { audit }) }, av: { available: false, error: "x" } }
        : path === "/api/v1/services/syslog" ? { forwarders: [{ address: "192.0.2.10", port: 514, proto: "udp" }], batchSize: 500, flushEvery: 2 }
          : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/services/status");
  await page.goto("/system/services/syslog/");
  await loaded;
}

test("a failing forwarder's audit backlog and error are shown in amber", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (err) => errors.push(String(err)));
  await open(page, {
    enabled: true, sent_total: 120, failed_total: 3, last_error: "tcp://192.0.2.11:6514: connection refused",
    last_flush: "2026-10-26T08:00:00Z", backlog: 57,
    forwarders: [
      { forwarder: "udp://192.0.2.10:514", last_id: 913, backlog: 0, last_error: "", last_sent: "2026-10-26T08:00:00Z" },
      { forwarder: "tcp://192.0.2.11:6514", last_id: 856, backlog: 57, last_error: "connection refused", last_sent: "" },
    ],
  });
  const panel = page.getByRole("region", { name: "Audit forwarding" });
  await expect(panel).toContainText("Sent: 120");
  await expect(panel).toContainText("Failed: 3");
  await expect(panel.getByText("Backlog: 57")).toHaveClass(/text-amber/);
  await expect(panel.getByRole("status", { name: "Audit forwarding error" })).toContainText("tcp://192.0.2.11:6514: connection refused");
  const row = (f: string) => panel.getByRole("row").filter({ has: page.getByRole("cell", { name: f, exact: true }) });
  await expect(row("tcp://192.0.2.11:6514")).toContainText("856");
  await expect(row("tcp://192.0.2.11:6514").getByRole("cell").nth(2)).toHaveClass(/text-amber/);
  await expect(row("tcp://192.0.2.11:6514").getByRole("cell").nth(3)).toHaveText("—");
  await expect(row("udp://192.0.2.10:514").getByRole("cell").nth(4)).toHaveText("—");
  expect(errors).toEqual([]);
});

test("healthy audit forwarding reads quietly", async ({ page }) => {
  await open(page, {
    enabled: true, sent_total: 9, failed_total: 0, last_error: "", last_flush: "", backlog: 0,
    forwarders: [{ forwarder: "udp://192.0.2.10:514", last_id: 9, backlog: 0, last_error: "", last_sent: "2026-10-26T08:00:00Z" }],
  });
  const panel = page.getByRole("region", { name: "Audit forwarding" });
  await expect(panel).toContainText("each forwarder resumes from its own cursor");
  await expect(panel.getByText("Backlog: 0")).not.toHaveClass(/text-amber/);
  await expect(panel.getByRole("status", { name: "Audit forwarding error" })).toHaveCount(0);
  await expect(panel).toContainText("Last flush: —");
});

test("a status without audit forwarding shows no audit panel", async ({ page }) => {
  await open(page, undefined);
  await expect(page.getByText("Sent: 40")).toBeVisible();
  await expect(page.getByRole("region", { name: "Audit forwarding" })).toHaveCount(0);
});

test("telemetry source loss and continuity are independent of audit forwarding and preserve drafts", async ({ page }) => {
  await page.clock.install();
  await open(page, { enabled: false, sent_total: 0, failed_total: 0, last_error: "", last_flush: "", backlog: 0, forwarders: [] });
  const panel = page.getByRole("region", { name: "Telemetry forwarding" });
  const engine = panel.getByRole("row").filter({ hasText: "tcp://192.0.2.11:6514" });
  await expect(engine).toContainText("engine");
  for (const [index, value] of [[1, "13"], [2, "21"], [3, "3"], [4, "7"], [5, "2"]] as const) {
    await expect(engine.getByRole("cell").nth(index)).toHaveText(value);
  }
  await expect(engine).toContainText("9223372036854775809");
  await expect(engine).toContainText("source offline");
  await expect(engine.getByRole("cell").nth(4)).toHaveClass(/text-rose-300/);
  await expect(panel).toContainText("additional loss is unknown");
  const services = panel.getByRole("row").filter({ hasText: "udp://192.0.2.10:514" });
  await expect(services).toContainText("services");
  await expect(services.getByRole("cell").nth(4)).toHaveText("0");
  const batch = page.locator('input[max="5000"]');
  await batch.fill("123");
  await page.getByLabel("Auto", { exact: true }).check();
  const refreshed = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/services/syslog");
  await page.clock.fastForward(15_000);
  await refreshed;
  await expect(batch).toHaveValue("123");
});
