import { expect, test, type Page } from "@playwright/test";

const alerts = [
  {
    id: "1", flowId: "tls-client", proto: "ids", kind: "alert",
    timestamp: "2026-11-10T12:00:00Z", srcIp: "192.0.2.10", dstIp: "192.0.2.20",
    srcPort: 49152, dstPort: 443, transport: "tcp",
    attributes: {
      message: "TLS ClientHello", severity: "high", rule_id: "TLS-CLIENT",
      event_proto: "tls", event_kind: "client_hello",
      event_attrs: { tls_legacy_version: "TLS1.2", tls_offered_versions: ["TLS1.3", "TLS1.2"] },
    },
  },
  {
    id: "2", flowId: "tls-server", proto: "ids", kind: "alert",
    timestamp: "2026-11-10T12:00:01Z", srcIp: "192.0.2.20", dstIp: "192.0.2.10",
    srcPort: 443, dstPort: 49152, transport: "tcp",
    attributes: {
      message: "TLS ServerHello", severity: "high", rule_id: "TLS-SERVER",
      event_proto: "tls", event_kind: "server_hello",
      event_attrs: { tls_legacy_version: "TLS1.2", tls_selected_version: "TLS1.3" },
    },
  },
  {
    id: "3", flowId: "http-request", proto: "ids", kind: "alert",
    timestamp: "2026-11-10T12:00:02Z", srcIp: "192.0.2.10", dstIp: "192.0.2.20",
    srcPort: 49152, dstPort: 80, transport: "tcp",
    attributes: {
      message: "HTTP request", severity: "medium", rule_id: "HTTP-REQUEST",
      event_proto: "http", event_kind: "request",
      event_attrs: { content_type: "application/json; charset=utf-8" },
    },
  },
  {
    id: "4", flowId: "http-response", proto: "ids", kind: "alert",
    timestamp: "2026-11-10T12:00:03Z", srcIp: "192.0.2.20", dstIp: "192.0.2.10",
    srcPort: 80, dstPort: 49152, transport: "tcp",
    attributes: {
      message: "HTTP response without content type", severity: "medium", rule_id: "HTTP-RESPONSE",
      event_proto: "http", event_kind: "response", event_attrs: {},
    },
  },
];

async function loadAlerts(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const json = path === "/api/v1/events" ? alerts
      : path.endsWith("/auth/me") || path.endsWith("/auth/session")
        ? { id: "admin", username: "containd", role: "admin" }
        : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  const answered = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/events");
  await page.goto("/alerts/");
  await answered;
}

function row(page: Page, label: string) {
  return page.locator("div.flex.justify-between").filter({ has: page.getByText(label, { exact: true }) });
}

test("alert details show the new TLS versions and HTTP content type", async ({ page }) => {
  await loadAlerts(page);

  await page.getByRole("cell", { name: "TLS ClientHello", exact: true }).click();
  await expect(row(page, "Legacy version")).toContainText("TLS1.2");
  await expect(row(page, "Offered versions")).toContainText("TLS1.3, TLS1.2");
  await expect(page.getByText("Selected version", { exact: true })).toHaveCount(0);
  await expect(page.getByText("TLS Version", { exact: true })).toHaveCount(0);

  await page.getByRole("cell", { name: "TLS ServerHello", exact: true }).click();
  await expect(row(page, "Legacy version")).toContainText("TLS1.2");
  await expect(row(page, "Selected version")).toContainText("TLS1.3");
  await expect(page.getByText("Offered versions", { exact: true })).toHaveCount(0);

  await page.getByRole("cell", { name: "HTTP request", exact: true }).click();
  await expect(row(page, "Content type")).toContainText("application/json; charset=utf-8");

  await page.getByRole("cell", { name: "HTTP response without content type", exact: true }).click();
  await expect(page.getByText("Content type", { exact: true })).toHaveCount(0);
});
