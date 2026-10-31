import { type Page } from "@playwright/test";
import type { FirewallRule, ICSPredicate, ICSPredicatePatch } from "../../lib/api";

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };

export async function openEditor(page: Page, surface: string, ics: ICSPredicate) {
  let stored: FirewallRule = { id: "selector", action: "ALLOW", protocols: [{ name: "tcp", port: "502" }], ics };
  const patches: { ics: ICSPredicatePatch }[] = [];
  const previews: FirewallRule[] = [];
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/firewall/rules/selector" && request.method() === "PATCH") {
      const patch = request.postDataJSON();
      patches.push(patch);
      const merged = { ...stored.ics, ...patch.ics } as Record<string, unknown>;
      for (const key of Object.keys(merged)) if (merged[key] === null) delete merged[key];
      stored = { ...stored, ...patch, ics: merged };
      await route.fulfill({ json: stored });
      return;
    }
    if (path === "/api/v1/firewall/rules/preview") {
      previews.push(request.postDataJSON());
      await route.fulfill({ json: { match_count: 0, sample_matches: [], time_range: null, total_events: 0 } });
      return;
    }
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/firewall/rules") body = [stored];
    if (path === "/api/v1/zones") body = [];
    if (path === "/api/v1/routing") body = { gateways: [], routes: [], rules: [] };
    if (path === "/api/v1/dataplane") body = { captureInterfaces: [], dpiMock: false, dpiMode: "monitor" };
    await route.fulfill({ json: body });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/firewall/rules");
  await page.goto(`/${surface}/`);
  await loaded;
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  return { patches, previews, saved: () => stored };
}
