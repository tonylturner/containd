import { expect, test, type Page, type Route } from "@playwright/test";

import type { DeploymentProfile, TLSInfo } from "../lib/api";

const servedFingerprint = Array(32).fill("AB").join(":");
const configuredFingerprint = Array(32).fill("CD").join(":");
const hint = "Default credentials on fresh installs: containd / containd.";

function tlsInfo(profile: DeploymentProfile): TLSInfo {
  return {
    managed: false,
    httpEnabled: profile === "training",
    httpEnabledSource: profile === "strict" ? "profile" : "default",
    ...(profile === "strict" ? { httpEnabledSaved: true, httpsEnabledSaved: false, hstsEnabledSaved: false } : {}),
    httpsEnabled: true,
    httpsEnabledSource: profile === "strict" ? "profile" : "config",
    hstsEnabled: profile === "strict",
    hstsEnabledSource: profile === "strict" ? "profile" : "config",
    httpListenAddr: ":8080", httpsListenAddr: ":8443",
    boundHttpListenAddr: profile === "training" ? "[::]:8080" : undefined,
    boundHttpsListenAddr: "[::]:8443",
    httpListenChanges: false, httpsListenChanges: false,
    // Same paths can hold a different configured leaf after a failed reload.
    servedCertFile: "/data/tls/server.pem", servedKeyFile: "/data/tls/server.pem",
    certFile: "/data/tls/server.pem", keyFile: "/data/tls/server.pem",
    servedCertFingerprintSHA256: servedFingerprint,
    certFingerprintSHA256: configuredFingerprint,
  };
}

async function mockAPI(page: Page, profile: DeploymentProfile, authenticated = false) {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/health") {
      return route.fulfill({ json: { profile, status: "ok", component: "containd" } });
    }
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") {
      return route.fulfill(authenticated
        ? { json: { id: "admin-1", username: "containd", role: "admin", profile } }
        : { status: 401, json: { error: "unauthorized" } });
    }
    if (path === "/api/v1/system/tls") return route.fulfill({ json: tlsInfo(profile) });
    return route.fulfill({ json: {} });
  });
}

async function noOverflow(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
}

function row(page: Page, label: string) {
  return page.locator("section").filter({ has: page.getByRole("heading", { name: "Management HTTPS" }) })
    .getByText(label, { exact: true }).locator("..");
}

for (const width of [1280, 390]) {
  for (const profile of ["training", "strict"] as const) {
    test(`${profile} login only hints training credentials at ${width}px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 1000 });
      await mockAPI(page, profile);
      const loaded = page.waitForResponse("**/api/v1/health");
      await page.goto("/login/");
      await loaded;
      await expect(page.getByLabel("Username", { exact: true })).toBeVisible();
      await expect(page.getByLabel("Password", { exact: true })).toBeVisible();
      if (profile === "training") await expect(page.getByText(hint, { exact: true })).toBeVisible();
      else {
        await expect(page.getByText(hint, { exact: true })).toHaveCount(0);
        await expect(page.locator("body")).not.toContainText(/one-time password|default credentials|containd \/ containd/i);
      }
      await noOverflow(page);
      if (process.env.PROFILE_UI_SCREENSHOTS) {
        await page.screenshot({ path: `${process.env.PROFILE_UI_SCREENSHOTS}/${profile}-login-${width}.png`, fullPage: true });
      }
    });

    test(`${profile} TLS policy, sources and separate fingerprints at ${width}px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 1000 });
      await page.addInitScript(() => localStorage.setItem("containd.auth.role", "admin"));
      await mockAPI(page, profile, true);
      const loaded = page.waitForResponse("**/api/v1/system/tls");
      await page.goto("/system/settings/");
      await loaded;
      await expect(page.getByRole("heading", { name: "Management HTTPS" })).toBeVisible();
      if (profile === "strict") {
        await expect(row(page, "HTTP enabled (next start)")).toContainText("Disabled · source: profile · saved: enabled");
        await expect(row(page, "HTTPS enabled (next start)")).toContainText("Enabled · source: profile · saved: disabled");
        await expect(row(page, "HSTS")).toContainText("Enabled · source: profile · saved: disabled");
        await expect(row(page, "Secure cookies")).toContainText("Enabled · source: profile");
        await expect(row(page, "HTTP listen")).toContainText("not bound");
      } else {
        await expect(row(page, "HTTP enabled (next start)")).toContainText("Enabled · source: default");
        await expect(row(page, "HTTPS enabled (next start)")).toContainText("Enabled · source: config");
        await expect(row(page, "HSTS")).toContainText("Disabled · source: config");
        await expect(row(page, "Secure cookies")).toContainText("Not reported by API");
        await expect(page.getByText(/The API does not report the effective cookie flag/)).toBeVisible();
        await expect(row(page, "HSTS")).not.toContainText("saved:");
      }
      const details = page.locator("details").filter({ has: page.getByText("Certificate details", { exact: true }) });
      await details.locator("summary").click();
      await expect(details).toHaveAttribute("open", "");
      await expect(row(page, "Served certificate SHA-256")).toContainText(servedFingerprint);
      await expect(row(page, "Configured certificate SHA-256")).toContainText(configuredFingerprint);
      // The full fingerprint must wrap inside the narrow card, not truncate.
      for (const label of ["Served certificate SHA-256", "Configured certificate SHA-256"]) {
        const bounds = await row(page, label).boundingBox();
        expect(bounds).not.toBeNull();
        expect(bounds!.x).toBeGreaterThanOrEqual(0);
        expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(width);
      }
      await noOverflow(page);
      if (process.env.PROFILE_UI_SCREENSHOTS) {
        await page.screenshot({ path: `${process.env.PROFILE_UI_SCREENSHOTS}/${profile}-tls-${width}.png`, fullPage: true });
      }
    });
  }
}

for (const scenario of ["pending", "missing", "failed"] as const) {
  test(`login has no credential hint when health is ${scenario}`, async ({ page }) => {
    await mockAPI(page, "training");
    let release: ((value: void) => void) | undefined;
    const pending = new Promise<void>((resolve) => { release = resolve; });
    await page.route("**/api/v1/health", async (route: Route) => {
      if (scenario === "pending") await pending;
      await route.fulfill(scenario === "failed"
        ? { status: 503, json: { error: "unavailable" } }
        : { json: { status: "ok", component: "containd" } });
    });
    const loaded = scenario === "pending" ? undefined : page.waitForResponse("**/api/v1/health");
    await page.goto("/login/");
    await loaded;
    await expect(page.getByLabel("Username", { exact: true })).toBeVisible();
    await expect(page.getByText(hint, { exact: true })).toHaveCount(0);
    release?.();
  });
}
