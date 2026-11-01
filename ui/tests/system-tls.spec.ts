import { expect, test, type Page } from "@playwright/test";

import { certUploadNotice, tlsView, type TLSRow } from "../app/system/settings/tls-view";

// Model tests: no page, no server.

const saved = {
  managed: false,
  httpEnabled: true, httpsEnabled: true, httpListenAddr: ":8080", httpsListenAddr: ":8443",
  certFile: "/etc/tls/server.crt", keyFile: "/etc/tls/server.key",
  certSubject: "CN=saved", certNotAfter: "2027-01-01T00:00:00Z",
  certDnsNames: ["saved.example"], certIps: ["192.0.2.20"],
};
const managedSaved = {
  ...saved, managed: true, certFile: "/data/tls/server.pem", keyFile: "/data/tls/server.pem",
};
// Bound listeners are named by their sockets' addresses: a wildcard listen
// is [::]. The API says whether the next start binds another listener.
const bound = { boundHttpListenAddr: "[::]:8080", boundHttpsListenAddr: "[::]:8443", httpListenChanges: false, httpsListenChanges: false };
const served = {
  servedCertSubject: "CN=served", servedCertNotAfter: "2026-12-01T00:00:00Z",
  servedCertDnsNames: ["served.example", "containd.local"], servedCertIps: ["192.0.2.10", "2001:db8::10"],
};
const iso = (v: string | undefined) => v ?? "—";
const rows = (list: TLSRow[]) => Object.fromEntries(list.map((r) => [r.label, r.value]));

test("listeners and files served now equal to the next start show once", () => {
  const view = tlsView({ ...saved, ...bound, ...served, servedCertFile: saved.certFile, servedKeyFile: saved.keyFile }, iso);
  expect(view).toEqual({
    rows: [
      { label: "HTTP listen", value: "[::]:8080" },
      { label: "HTTPS listen", value: "[::]:8443" },
      { label: "Cert file", value: "/etc/tls/server.crt" },
      { label: "Key file", value: "/etc/tls/server.key" },
      { label: "Cert subject", value: "CN=served" },
      { label: "Cert SANs", value: "served.example, containd.local, 192.0.2.10, 2001:db8::10" },
      { label: "Cert expires", value: "2026-12-01T00:00:00Z" },
    ],
  });
});

test("each certificate shows its own subject alternative names", () => {
  // A certificate without SANs says so; no certificate read shows nothing.
  const none = tlsView({ ...saved, ...bound, ...served, servedCertDnsNames: [], servedCertIps: undefined, servedCertFile: saved.certFile, servedKeyFile: saved.keyFile }, iso);
  expect(rows(none.rows)["Cert SANs"]).toBe("none");
  const unread = tlsView({ ...saved, ...bound, servedCertFile: saved.certFile, servedKeyFile: saved.keyFile }, iso);
  expect(rows(unread.rows)["Cert SANs"]).toBe("—");
  // Saved and served certificates that differ keep their SANs apart.
  const differ = tlsView({ ...saved, ...bound, ...served, servedCertFile: "/data/tls/default.crt", servedKeyFile: "/data/tls/default.key" }, iso);
  expect(rows(differ.rows)).toMatchObject({
    "Cert SANs": "served.example, containd.local, 192.0.2.10, 2001:db8::10",
    "Cert SANs (next start)": "saved.example, 192.0.2.20",
  });
});

test("saved files that differ from the served ones are served from the next start", () => {
  const view = tlsView({ ...saved, ...bound, ...served, servedCertFile: "/data/tls/default.crt", servedKeyFile: "/etc/tls/server.key" }, iso);
  expect(rows(view.rows)).toMatchObject({
    "Cert file": "/data/tls/default.crt",
    "Cert expires": "2026-12-01T00:00:00Z",
    "Cert file (next start)": "/etc/tls/server.crt",
    "Cert subject (next start)": "CN=saved",
    "Cert expires (next start)": "2027-01-01T00:00:00Z",
  });
  expect(view.note).toBe("The saved files differ from the served ones; they are served from the next management start.");
});

test("listeners that the next start binds differently show both", () => {
  const view = tlsView({
    ...saved, httpEnabled: false, httpsListenAddr: ":9443", ...bound, httpListenChanges: true, httpsListenChanges: true,
    ...served, servedCertFile: saved.certFile, servedKeyFile: saved.keyFile,
  }, iso);
  expect(view.rows.slice(0, 4)).toEqual([
    { label: "HTTP listen", value: "[::]:8080" },
    { label: "HTTP listen (next start)", value: "disabled" },
    { label: "HTTPS listen", value: "[::]:8443" },
    { label: "HTTPS listen (next start)", value: ":9443" },
  ]);
  expect(view.note).toBeUndefined();
});

test("a listener bound at a specific address in place of the wildcard shows the next start", () => {
  const view = tlsView({ ...saved, ...bound, boundHttpListenAddr: "192.0.2.10:8080", httpListenChanges: true, ...served, servedCertFile: saved.certFile, servedKeyFile: saved.keyFile }, iso);
  expect(view.rows.slice(0, 3)).toEqual([
    { label: "HTTP listen", value: "192.0.2.10:8080" },
    { label: "HTTP listen (next start)", value: ":8080" },
    { label: "HTTPS listen", value: "[::]:8443" },
  ]);
});

test("without a bound HTTPS listener the saved files wait for the next start", () => {
  const view = tlsView({ ...saved, boundHttpListenAddr: "[::]:8080", httpListenChanges: false, httpsListenChanges: true }, iso);
  expect(rows(view.rows)).toEqual({
    "HTTP listen": "[::]:8080",
    "HTTPS listen": "not bound",
    "HTTPS listen (next start)": ":8443",
    "Cert file": "no HTTPS listener bound",
    "Key file": "no HTTPS listener bound",
    "Cert file (next start)": "/etc/tls/server.crt",
    "Key file (next start)": "/etc/tls/server.key",
    "Cert subject (next start)": "CN=saved",
    "Cert SANs (next start)": "saved.example, 192.0.2.20",
    "Cert expires (next start)": "2027-01-01T00:00:00Z",
  });
  expect(view.note).toBe("No HTTPS listener is bound; the saved files are served from the next management start.");
});

test("saved files are not pending when the next start binds no HTTPS", () => {
  const view = tlsView({ ...saved, httpsEnabled: false, ...bound, ...served, servedCertFile: "/data/tls/default.crt", servedKeyFile: "/data/tls/default.key" }, iso);
  expect(view.note).toBeUndefined();
  expect(view.rows.map((r) => r.label)).not.toContain("Cert file (next start)");
  expect(tlsView(null).rows.every((r) => r.value === "—")).toBe(true);
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

test("reload failures preserve the served certificate readout", () => {
  const info = { ...saved, ...bound, ...served, servedCertFile: saved.certFile, servedKeyFile: saved.keyFile };
  const healthy = tlsView(info, iso);
  const failed = tlsView({ ...info, reloadError: "tls: private key does not match public key" }, iso);
  expect(failed.rows).toEqual(healthy.rows);
  expect(failed.reloadError).toBe("Certificate reload failed. The listener still serves the last valid certificate. tls: private key does not match public key");
  expect(healthy.reloadError).toBeUndefined();
  expect(tlsView({ ...info, reloadError: "" }, iso).reloadError).toBeUndefined();
});

test("identity bundles show one path for served and next-start identities", () => {
  const view = tlsView({
    ...managedSaved, ...bound, ...served,
    servedCertFile: "/etc/tls/identity.pem", servedKeyFile: "/etc/tls/identity.pem",
  }, iso);
  expect(rows(view.rows)).toMatchObject({
    "Identity bundle": "/etc/tls/identity.pem",
    "Identity bundle (next start)": "/data/tls/server.pem",
    "Cert subject": "CN=served",
    "Cert subject (next start)": "CN=saved",
  });
  expect(view.rows.some((row) => /^(Cert|Key) file/.test(row.label))).toBe(false);
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
      await route.fulfill({ json: user, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
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
    "/api/v1/system/tls": { json: { ...saved, ...bound, ...served, servedCertFile: "/data/tls/default.crt", servedKeyFile: "/data/tls/default.key" } },
  });
  const card = await openSettings(page);
  await expect(card.getByText("/data/tls/default.crt")).toBeVisible();
  await expect(card.getByText("CN=served")).toBeVisible();
  await expect(card.getByText("served.example, containd.local, 192.0.2.10, 2001:db8::10")).toBeVisible();
  await expect(card.getByText("Cert SANs (next start)")).toBeVisible();
  await expect(card.getByText("saved.example, 192.0.2.20")).toBeVisible();
  await expect(card.getByText("Cert file (next start)")).toBeVisible();
  await expect(card.getByText("/etc/tls/server.crt")).toBeVisible();
  await expect(card.getByText("they are served from the next management start")).toBeVisible();
  await expect(card.getByText("[::]:8080")).toBeVisible();
  await expect(card.getByText(/listen \(next start\)/)).toHaveCount(0);
});

for (const width of [1280, 390]) {
  test(`reload failure is visible and clears after recovery at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 1000 });
    const identity = {
      ...managedSaved, ...bound, ...served,
      servedCertFile: "/data/tls/server.pem", servedKeyFile: "/data/tls/server.pem",
    };
    await mockAPI(page, { "/api/v1/system/tls": { json: identity } });
    const card = await openSettings(page);
    const notice = card.getByRole("alert", { name: "Certificate reload failed" });
    await expect(card.getByText("CN=served")).toBeVisible();
    await expect(notice).toHaveCount(0);
    await expect(card.getByText("Identity bundle", { exact: true })).toBeVisible();
    await expect(card.getByText("/data/tls/server.pem", { exact: true })).toHaveCount(1);
    await expect(card.getByText(/^(Cert|Key) file$/)).toHaveCount(0);
    await expect(card.getByRole("button", { name: "Upload cert/key" })).toBeEnabled();
    await expect(card.getByRole("note", { name: "External identity (read-only)" })).toHaveCount(0);

    await page.route("**/api/v1/system/tls", (route) => route.fulfill({
      json: { ...identity, reloadError: "read /data/tls/server.pem: tls: private key does not match public key" },
    }));
    await card.getByRole("button", { name: "Refresh" }).click();
    await expect(notice).toContainText("The listener still serves the last valid certificate.");
    await expect(notice).toContainText("read /data/tls/server.pem: tls: private key does not match public key");
    await expect(notice).toHaveCSS("color", "rgb(254, 205, 211)");
    await expect(notice).toHaveCSS("border-color", "oklab(0.645039 0.206618 0.0609754 / 0.3)");
    await expect(card.getByText("CN=served")).toBeVisible();
    await notice.scrollIntoViewIfNeeded();
    const bounds = await notice.boundingBox();
    expect(bounds).not.toBeNull();
    expect(bounds!.x).toBeGreaterThanOrEqual(0);
    expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(width);
    if (process.env.TLS_UI_SCREENSHOTS) {
      await page.screenshot({ path: `${process.env.TLS_UI_SCREENSHOTS}/reload-failure-${width}.png`, fullPage: true });
    }

    await page.route("**/api/v1/system/tls", (route) => route.fulfill({ json: identity }));
    await card.getByRole("button", { name: "Refresh" }).click();
    await expect(notice).toHaveCount(0);
    await expect(card.getByText("CN=served")).toBeVisible();
  });
}

test("stored certificate upload is a warning, not an update", async ({ page }) => {
  const warning = "the HTTPS listener serves \"/data/tls/default.crt\"; the certificate is served from the next management start";
  await mockAPI(page, {
    "/api/v1/system/tls": { json: { ...managedSaved, servedCertFile: "/data/tls/default.crt", servedKeyFile: "/data/tls/default.key" } },
    "/api/v1/system/tls/cert": {
      json: { status: "stored", warnings: [warning] },
      headers: { "X-Containd-Warnings": warning },
    },
  });
  await uploadCert(page);
  await expect(page.getByRole("status").filter({ hasText: `Certificate stored but not served yet: ${warning}` })).toBeVisible();
  await expect(page.getByText(/Certificate updated/)).toHaveCount(0);
});

for (const width of [1280, 390]) {
  test(`external identities are read-only and retain reload status at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 1000 });
    const identity = {
      ...saved, ...bound, ...served,
      certFile: "/etc/tls/server.crt", keyFile: "/etc/tls/server.key",
      servedCertFile: "/etc/tls/server.crt", servedKeyFile: "/etc/tls/server.key",
    };
    await mockAPI(page, {
      "/api/v1/system/tls": { json: identity },
    });
    const card = await openSettings(page);
    const readOnly = card.getByRole("note", { name: "External identity (read-only)" });
    await expect(readOnly).toContainText("external files that containd does not rewrite");
    await expect(readOnly).toContainText("Rotate them at their source; containd reloads them on change.");
    await expect(card.getByRole("button", { name: /Upload|Regenerate/i })).toHaveCount(0);
    await expect(card.locator('input[type="file"]')).toHaveCount(0);
    await expect(card.getByText("/etc/tls/server.crt", { exact: true })).toBeVisible();
    await expect(card.getByText("/etc/tls/server.key", { exact: true })).toBeVisible();
    await expect(card.getByText("CN=served")).toBeVisible();
    await expect(page.getByRole("button", { name: "Upload CA bundle" })).toBeEnabled();
    if (process.env.TLS_UI_SCREENSHOTS) {
      await readOnly.scrollIntoViewIfNeeded();
      await page.screenshot({ path: `${process.env.TLS_UI_SCREENSHOTS}/external-read-only-${width}.png`, fullPage: true });
    }

    await page.route("**/api/v1/system/tls", (route) => route.fulfill({
      json: { ...identity, reloadError: "tls: private key does not match public key" },
    }));
    await card.getByRole("button", { name: "Refresh" }).click();
    const failure = card.getByRole("alert", { name: "Certificate reload failed" });
    await expect(failure).toContainText("The listener still serves the last valid certificate.");
    await expect(failure).toContainText("tls: private key does not match public key");
    await expect(readOnly).toBeVisible();
    await expect(card.getByText("CN=served")).toBeVisible();
    await expect(card.getByRole("button", { name: /Upload|Regenerate/i })).toHaveCount(0);
    if (process.env.TLS_UI_SCREENSHOTS) {
      await failure.scrollIntoViewIfNeeded();
      await page.screenshot({ path: `${process.env.TLS_UI_SCREENSHOTS}/external-reload-failure-${width}.png`, fullPage: true });
    }
  });
}

test("the API mode controls uploads even when external paths match the managed bundle", async ({ page }) => {
  const identity = {
    ...managedSaved, managed: false, ...bound, ...served,
    servedCertFile: managedSaved.certFile, servedKeyFile: managedSaved.keyFile,
  };
  await mockAPI(page, { "/api/v1/system/tls": { json: identity } });
  const card = await openSettings(page);
  await expect(card.getByRole("note", { name: "External identity (read-only)" })).toBeVisible();
  await expect(card.getByRole("button", { name: "Upload cert/key" })).toHaveCount(0);

  await page.route("**/api/v1/system/tls", (route) => route.fulfill({ json: { ...identity, managed: true } }));
  await card.getByRole("button", { name: "Refresh" }).click();
  await expect(card.getByRole("button", { name: "Upload cert/key" })).toBeEnabled();
  await expect(card.locator('input[type="file"]')).toHaveCount(2);
  await expect(card.getByRole("note", { name: "External identity (read-only)" })).toHaveCount(0);
  const pem = Buffer.from("-----BEGIN CERTIFICATE-----\n");
  await card.locator('input[type="file"]').nth(0).setInputFiles({ name: "server.crt", mimeType: "application/x-pem-file", buffer: pem });
  await card.locator('input[type="file"]').nth(1).setInputFiles({ name: "server.key", mimeType: "application/x-pem-file", buffer: pem });

  await page.route("**/api/v1/system/tls", (route) => route.fulfill({ json: identity }));
  await card.getByRole("button", { name: "Refresh" }).click();
  await expect(card.getByRole("button", { name: "Upload cert/key" })).toHaveCount(0);
  await expect(card.locator('input[type="file"]')).toHaveCount(0);

  await page.route("**/api/v1/system/tls", (route) => route.fulfill({ json: { ...identity, managed: true } }));
  await card.getByRole("button", { name: "Refresh" }).click();
  await card.getByRole("button", { name: "Upload cert/key" }).click();
  await expect(page.getByText("Select both certificate and private key PEM files.")).toBeVisible();
});

test("a managed certificate upload remains available", async ({ page }) => {
  await mockAPI(page, {
    "/api/v1/system/tls": { json: { ...managedSaved, ...bound, ...served, servedCertFile: managedSaved.certFile, servedKeyFile: managedSaved.keyFile } },
    "/api/v1/system/tls/cert": { json: { status: "updated" } },
  });
  await uploadCert(page);
  await expect(page.getByText("Certificate updated. New connections will use it immediately.")).toBeVisible();
});

test("a rejected certificate shows the server's reason", async ({ page }) => {
  await mockAPI(page, {
    "/api/v1/system/tls": { json: managedSaved },
    "/api/v1/system/tls/cert": { status: 400, json: { error: "invalid cert/key pair", detail: "tls: private key does not match public key" } },
  });
  await uploadCert(page);
  await expect(page.getByText("invalid cert/key pair: tls: private key does not match public key")).toBeVisible();
});
