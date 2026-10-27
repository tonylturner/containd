import { expect, test, type Page } from "@playwright/test";

import { certUploadNotice, tlsView, type TLSRow } from "../app/system/settings/tls-view";

// Model tests: no page, no server.

const saved = {
  httpEnabled: true, httpsEnabled: true, httpListenAddr: ":8080", httpsListenAddr: ":8443",
  certFile: "/data/tls/server.crt", keyFile: "/data/tls/server.key",
  certSubject: "CN=saved", certNotAfter: "2027-01-01T00:00:00Z",
  certDnsNames: ["saved.example"], certIps: ["192.0.2.20"],
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
      { label: "Cert file", value: "/data/tls/server.crt" },
      { label: "Key file", value: "/data/tls/server.key" },
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
  const view = tlsView({ ...saved, ...bound, ...served, servedCertFile: "/data/tls/default.crt", servedKeyFile: "/data/tls/server.key" }, iso);
  expect(rows(view.rows)).toMatchObject({
    "Cert file": "/data/tls/default.crt",
    "Cert expires": "2026-12-01T00:00:00Z",
    "Cert file (next start)": "/data/tls/server.crt",
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
    "Cert file (next start)": "/data/tls/server.crt",
    "Key file (next start)": "/data/tls/server.key",
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
    "/api/v1/system/tls": { json: { ...saved, ...bound, ...served, servedCertFile: "/data/tls/default.crt", servedKeyFile: "/data/tls/default.key" } },
  });
  const card = await openSettings(page);
  await expect(card.getByText("/data/tls/default.crt")).toBeVisible();
  await expect(card.getByText("CN=served")).toBeVisible();
  await expect(card.getByText("served.example, containd.local, 192.0.2.10, 2001:db8::10")).toBeVisible();
  await expect(card.getByText("Cert SANs (next start)")).toBeVisible();
  await expect(card.getByText("saved.example, 192.0.2.20")).toBeVisible();
  await expect(card.getByText("Cert file (next start)")).toBeVisible();
  await expect(card.getByText("/data/tls/server.crt")).toBeVisible();
  await expect(card.getByText("they are served from the next management start")).toBeVisible();
  await expect(card.getByText("[::]:8080")).toBeVisible();
  await expect(card.getByText(/listen \(next start\)/)).toHaveCount(0);
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

test("a rejected certificate shows the server's reason", async ({ page }) => {
  await mockAPI(page, {
    "/api/v1/system/tls": { json: saved },
    "/api/v1/system/tls/cert": { status: 400, json: { error: "invalid cert/key pair", detail: "tls: private key does not match public key" } },
  });
  await uploadCert(page);
  await expect(page.getByText("invalid cert/key pair: tls: private key does not match public key")).toBeVisible();
});
