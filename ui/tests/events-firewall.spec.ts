import { expect, test } from "@playwright/test";
import type { TelemetryEvent } from "../lib/api";

const ruleHit: TelemetryEvent = {
  id: "101",
  flowId: "flow-101",
  proto: "",
  kind: "firewall.rule.hit",
  timestamp: "2026-11-11T08:00:00Z",
  attributes: { ruleId: "deny-plc-write", action: "DENY", via: "nflog" },
};

test("firewall rule hits have a decision headline and match the firewall category", async ({ page }) => {
  const queries: URL[] = [];
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    if (path === "/api/v1/events") queries.push(url);
    const body = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin", username: "containd", role: "admin" }
      : path === "/api/v1/events" ? { events: [ruleHit], historyTruncated: false }
        : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });

  const loaded = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/v1/events");
  await page.goto("/events/");
  await loaded;
  await expect(page.getByText("Firewall decision", { exact: true })).toBeVisible();
  await expect(page.getByText("Telemetry event", { exact: true })).toHaveCount(0);

  const filtered = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return url.pathname === "/api/v1/events" && url.searchParams.get("category") === "firewall";
  });
  await page.getByRole("button", { name: "Firewall decisions", exact: true }).click();
  await filtered;
  expect(queries.at(-1)?.searchParams.get("category")).toBe("firewall");
  await expect(page.getByText("Firewall decision", { exact: true })).toBeVisible();
});
