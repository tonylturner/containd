import { expect, test, type Page } from "@playwright/test";

import { certUploadNotice, tlsFilesView } from "../app/system/settings/tls-view";

// Model tests: no page, no server.

const saved = { httpEnabled: true, httpsEnabled: true, certFile: "/data/tls/server.crt", keyFile: "/data/tls/server.key" };

test("served files equal to the saved ones are not pending", () => {
  const view = tlsFilesView({ ...saved, servedCertFile: "/data/tls/server.crt", servedKeyFile: "/data/tls/server.key" });
  expect(view).toEqual({
    servedCert: "/data/tls/server.crt",
    servedKey: "/data/tls/server.key",
    savedCert: "/data/tls/server.crt",
    savedKey: "/data/tls/server.key",
    pending: false,
  });
});

test("saved files that differ from the served ones are served from the next start", () => {
  const view = tlsFilesView({ ...saved, servedCertFile: "/data/tls/default.crt", servedKeyFile: "/data/tls/server.key" });
  expect(view.servedCert).toBe("/data/tls/default.crt");
  expect(view.pending).toBe(true);
  expect(view.pendingNote).toBe("The saved files differ from the served ones; they are served from the next management start.");
});

test("without a bound HTTPS listener the saved files wait for the next start", () => {
  const view = tlsFilesView(saved);
  expect(view.servedCert).toBe("no HTTPS listener bound");
  expect(view.servedKey).toBe("no HTTPS listener bound");
  expect(view.pending).toBe(true);
  expect(view.pendingNote).toBe("No HTTPS listener is bound; the saved files are served from the next management start.");
});

test("saved files are not pending when the next start binds no HTTPS", () => {
  const view = tlsFilesView({ ...saved, httpsEnabled: false, servedCertFile: "/data/tls/default.crt", servedKeyFile: "/data/tls/default.key" });
  expect(view.pending).toBe(false);
  expect(view.pendingNote).toBeUndefined();
  expect(tlsFilesView(null)).toEqual({ servedCert: "—", servedKey: "—", savedCert: "—", savedKey: "—", pending: false });
});

test("certificate upload notices follow the upload status", () => {
  expect(certUploadNotice({ ok: true, data: { status: "updated", warnings: [] } })).toEqual({
    kind: "status", text: "Certificate updated. New connections will use it immediately.",
  });
  expect(certUploadNotice({
    ok: true,
    data: { status: "stored", warnings: ["the HTTPS listener serves \"/data/tls/default.crt\"; the certificate is served from the next management start"] },
    warning: "header text",
  })).toEqual({
    kind: "warning",
    text: "Certificate stored but not served yet: the HTTPS listener serves \"/data/tls/default.crt\"; the certificate is served from the next management start",
  });
  // The X-Containd-Warnings header stands in for a body without warnings.
  expect(certUploadNotice({ ok: true, data: { status: "stored" }, warning: "no HTTPS listener is bound" })).toEqual({
    kind: "warning", text: "Certificate stored but not served yet: no HTTPS listener is bound",
  });
  expect(certUploadNotice({ ok: true, data: { status: "stored" } }).text).toBe("Certificate stored but not served yet.");
  expect(certUploadNotice({ ok: false, error: "conflict" })).toEqual({ kind: "error", text: "conflict" });
});

// Page tests.

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };

async function mockAPI(page: Page, routes: Record<string, { status?: number; json: unknown; headers?: Record<string, string> }>) {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") {
      await route.fulfill({ json: user });
      return;
    }
    await route.fulfill(routes[path] ?? { json: {} });
  });
}

async function openSettings(page: Page) {
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/system/tls");
  await page.goto("/system/settings/");
  await loaded;
  return page.locator("section").filter({ hasText: "Management HTTPS" });
}

async function uploadCert(page: Page) {
  const card = await openSettings(page);
  const pem = Buffer.from("-----BEGIN CERTIFICATE-----\n");
  await card.locator('input[type="file"]').nth(0).setInputFiles({ name: "server.crt", mimeType: "application/x-pem-file", buffer: pem });
  await card.locator('input[type="file"]').nth(1).setInputFiles({ name: "server.key", mimeType: "application/x-pem-file", buffer: pem });
  await card.getByRole("button", { name: "Upload cert/key" }).click();
}

test("settings page marks saved files that differ from the served ones", async ({ page }) => {
  await mockAPI(page, {
    "/api/v1/system/tls": { json: { ...saved, servedCertFile: "/data/tls/default.crt", servedKeyFile: "/data/tls/default.key" } },
  });
  const card = await openSettings(page);
  await expect(card.getByText("Served cert file")).toBeVisible();
  await expect(card.getByText("/data/tls/default.crt")).toBeVisible();
  await expect(card.getByText("Cert file (next start)")).toBeVisible();
  await expect(card.getByText("/data/tls/server.crt")).toBeVisible();
  await expect(card.getByText("they are served from the next management start")).toBeVisible();
});

test("stored certificate upload is a warning, not an update", async ({ page }) => {
  const warning = "the HTTPS listener serves \"/data/tls/default.crt\"; the certificate is served from the next management start";
  await mockAPI(page, {
    "/api/v1/system/tls": { json: { ...saved, servedCertFile: "/data/tls/default.crt", servedKeyFile: "/data/tls/default.key" } },
    "/api/v1/system/tls/cert": {
      json: { status: "stored", warnings: [warning] },
      headers: { "X-Containd-Warnings": warning },
    },
  });
  await uploadCert(page);
  await expect(page.getByRole("status").filter({ hasText: `Certificate stored but not served yet: ${warning}` })).toBeVisible();
  await expect(page.getByText(/Certificate updated/)).toHaveCount(0);
});

test("a certificate upload that would split the served pair shows the conflict", async ({ page }) => {
  const conflict = "the HTTPS listener serves certificate \"/data/tls/server.crt\" with key \"/data/tls/default.key\"; writing certificate \"/data/tls/server.crt\" (source: system.mgmt.tlsCertFile) and key \"/data/tls/server.key\" (source: system.mgmt.tlsKeyFile) would pair a new file with a served one";
  await mockAPI(page, {
    "/api/v1/system/tls": { json: { ...saved, servedCertFile: "/data/tls/server.crt", servedKeyFile: "/data/tls/default.key" } },
    "/api/v1/system/tls/cert": { status: 409, json: { error: conflict } },
  });
  await uploadCert(page);
  await expect(page.getByText(conflict)).toBeVisible();
  await expect(page.getByText(/Certificate (updated|stored)/)).toHaveCount(0);
});
