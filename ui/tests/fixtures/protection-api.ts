import { expect, type Page } from "@playwright/test";
import type { ProtectionStatus } from "../../lib/api-protection";

export function observation(overrides: Partial<ProtectionStatus> = {}): ProtectionStatus {
  return {
    bootId: "boot-a", applyId: "apply-a", installedApplyId: "apply-a",
    state: "protecting", retryable: false, observedAt: "2026-10-31T12:00:00Z",
    components: [{ name: "nft", required: true, state: "ready", reason: "", since: "2026-10-31T12:00:00Z" }],
    effects: [{ traffic: "IEC 104 commands", effect: "normal" }],
    ...overrides,
  };
}

/** Register after catch-all API handlers. Layout tests default to a healthy engine;
 * protection-specific tests can supply a different complete observation. */
export async function mockProtection(page: Page, status: ProtectionStatus = observation()) {
  await page.route("**/api/v1/dataplane/protection", (route) => route.fulfill({ json: status }));
}

export async function protectionAPI(page: Page, initial: ProtectionStatus, options: {
  role?: "admin" | "view";
  enforcement?: "enforcing" | "degraded" | "disabled" | "unavailable" | "unknown";
  enforcementReason?: string;
} = {}) {
  const mock = {
    status: initial as unknown, readStatus: 200, reads: 0,
    retryStatus: 202, retryCode: "", retries: [] as unknown[],
    afterRetry: undefined as ProtectionStatus | undefined,
  };
  const role = options.role ?? "admin";
  await page.addInitScript((role) => {
    localStorage.setItem("containd.auth.role", role);
    sessionStorage.setItem("containd.session.token", "test-token");
  }, role);
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/dataplane/protection") {
      mock.reads++;
      await route.fulfill({ status: mock.readStatus, json: mock.status });
      return;
    }
    if (path === "/api/v1/dataplane/protection/retry") {
      mock.retries.push(route.request().postDataJSON());
      if (mock.afterRetry) mock.status = mock.afterRetry;
      await route.fulfill({
        status: mock.retryStatus,
        json: mock.retryStatus === 202 ? { status: "retrying", applyId: initial.applyId }
          : { code: mock.retryCode, error: "protection retry refused" },
      });
      return;
    }
    const bodies: Record<string, unknown> = {
      "/api/v1/auth/me": { id: "operator", username: "operator", role },
      "/api/v1/auth/session": { id: "operator", username: "operator", role },
      "/api/v1/health": {
        status: "ok", component: "mgmt", evidence: { state: "ok" },
        enforcement: { state: options.enforcement ?? "unavailable", reason: options.enforcementReason ?? "protection pending" },
        protection: { state: initial.state, applyId: initial.applyId },
      },
      "/api/v1/config": { zones: [{ name: "it" }], interfaces: [{ name: "lan1", device: "eth0", zone: "it" }], routing: { gateways: [], routes: [], rules: [] }, firewall: { rules: [] } },
      "/api/v1/config/diff": { changed: false, changedSections: [] },
      "/api/v1/zones": [],
      "/api/v1/interfaces/state": [],
      "/api/v1/flows": [],
      "/api/v1/events": [],
      "/api/v1/firewall/rules": [],
      "/api/v1/conntrack": [],
      "/api/v1/dataplane/ruleset/status": { installed: true, error: "old uncorrelated ruleset error" },
      "/api/v1/routing": { gateways: [], routes: [], rules: [] },
      "/api/v1/dataplane": { captureInterfaces: [], dpiMock: false },
    };
    await route.fulfill({ json: bodies[path] ?? {}, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  return mock;
}

export async function openProtection(page: Page, path = "/zones/") {
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/dataplane/protection");
  await page.goto(path);
  await loaded;
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
}
