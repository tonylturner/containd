import { expect, test, type Page } from "@playwright/test";
import type { OpenVPNCredential } from "../lib/api-vpn";

const prefix = "/api/v1/services/vpn/openvpn/clients";
const active: OpenVPNCredential = {
  id: `${"a".repeat(64)}:01`,
  issuer: "a".repeat(64),
  serial: "01",
  name: "operator",
  issuedAt: "2026-10-30T10:00:00Z",
  expiresAt: "2031-10-30T10:00:00Z",
};
const revoked: OpenVPNCredential = {
  ...active, id: `${active.issuer}:02`, serial: "02", name: "retired",
  revokedAt: "2026-10-31T09:00:00Z",
};

async function openClients(page: Page, revocationsApplied = false) {
  const server = {
    clients: structuredClone([active, revoked]),
    revocationsApplied,
    writes: [] as { path: string; body: unknown }[],
    downloads: [] as string[],
    createStatus: 200,
    downloadStatus: 200,
    revokeStatus: 200,
    revokeDurable: true,
    listStatus: 200,
  };
  await page.addInitScript(() => localStorage.setItem("containd.auth.role", "admin"));
  await page.route("**/api/v1/**", async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    if (path === prefix) {
      if (req.method() === "GET") {
        return route.fulfill({ status: server.listStatus, json: server.listStatus === 200 ? { clients: server.clients, revocationsApplied: server.revocationsApplied } : { error: "authority unavailable" } });
      }
      const body = req.postDataJSON();
      server.writes.push({ path, body });
      if (server.createStatus !== 200) {
        return route.fulfill({ status: server.createStatus, json: { error: server.createStatus === 400 ? "invalid client name" : "client name already issued" } });
      }
      const credential = { ...active, name: body.name, id: `${active.issuer}:03`, serial: "03" };
      server.clients.push(credential);
      return route.fulfill({ json: credential });
    }
    if (path.startsWith(`${prefix}/`)) {
      const id = decodeURIComponent(path.slice(prefix.length + 1).replace(/\/revoke$/, ""));
      if (req.method() === "GET") {
        server.downloads.push(id);
        return route.fulfill(server.downloadStatus === 200 ? {
          contentType: "application/x-openvpn-profile",
          headers: { "Content-Disposition": `attachment; filename="${id}.ovpn"` },
          body: "client\n<ca>\ncertificate\n</ca>\n",
        } : { status: server.downloadStatus, json: { error: "managed server not active" } });
      }
      server.writes.push({ path, body: req.postData() });
      if (server.revokeStatus === 503 && !server.revokeDurable) {
        return route.fulfill({ status: 503, json: { error: "credential authority unavailable" } });
      }
      if (server.revokeStatus !== 200 && server.revokeStatus !== 503) {
        return route.fulfill({ status: server.revokeStatus, json: { error: "unknown credential ID" } });
      }
      const credential = { ...server.clients.find((c) => c.id === id)!, revokedAt: revoked.revokedAt };
      server.clients = server.clients.map((c) => c.id === id ? credential : c);
      server.revocationsApplied = server.revokeStatus === 200;
      return route.fulfill({
        status: server.revokeStatus,
        json: { credential, revoked: true, applied: server.revokeStatus === 200, ...(server.revokeStatus === 503 ? { error: "revoked, runtime not confirmed" } : {}) },
      });
    }
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = { id: "admin", username: "containd", role: "admin" };
    if (path === "/api/v1/services/vpn") body = {
      wireguard: { enabled: false },
      openvpn: { enabled: true, mode: "server", server: { listenPort: 1194, proto: "udp", tunnelCIDR: "10.9.0.0/24", publicEndpoint: "vpn.example.test" } },
    };
    if (["/api/v1/interfaces/state", "/api/v1/interfaces", "/api/v1/zones"].includes(path)) body = [];
    if (path === "/api/v1/config/diff") body = { changed: false, changedSections: [] };
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  await Promise.all([page.waitForResponse((res) => new URL(res.url()).pathname === prefix), page.goto("/vpn/")]);
  await expect(page.getByRole("region", { name: "OpenVPN client credentials" })).toBeVisible();
  return server;
}

function row(page: Page, name = active.name) {
  return page.getByRole("region", { name: "OpenVPN client credentials" }).getByText(name, { exact: true }).locator("../..");
}

async function confirmRevoke(page: Page) {
  await row(page).getByRole("button", { name: "Revoke", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Revoke client credential?" });
  await expect(dialog).toContainText("All clients will reconnect once");
  await dialog.getByRole("button", { name: "Revoke", exact: true }).click();
}

async function confirmCreate(page: Page) {
  await page.getByRole("button", { name: "Create", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Create client credential?" });
  await expect(dialog).toContainText("independent of Save");
  await dialog.getByRole("button", { name: "Create", exact: true }).click();
}

test("lists credential identity, dates and revoked state without mutations", async ({ page }) => {
  const server = await openClients(page);
  await expect(row(page)).toContainText(active.id);
  await expect(row(page)).toContainText("Serial: 01");
  await expect(row(page).locator("time").nth(0)).toHaveAttribute("datetime", active.issuedAt);
  await expect(row(page).locator("time").nth(1)).toHaveAttribute("datetime", active.expiresAt);
  await expect(row(page)).toContainText("active");
  await expect(row(page, revoked.name)).toContainText("revoked");
  expect(server.writes).toEqual([]);
});

test("creates and displays the returned credential", async ({ page }) => {
  const server = await openClients(page);
  await page.getByRole("textbox", { name: "Client name" }).fill("engineer");
  await confirmCreate(page);
  await expect(row(page, "engineer")).toContainText(`${active.issuer}:03`);
  await expect(page.getByRole("textbox", { name: "Client name" })).toHaveValue("");
  expect(server.writes).toEqual([{ path: prefix, body: { name: "engineer" } }]);
});

for (const status of [400, 409]) {
  test(`create displays the API's ${status} error`, async ({ page }) => {
    const server = await openClients(page);
    server.createStatus = status;
    await page.getByRole("textbox", { name: "Client name" }).fill("operator");
    await confirmCreate(page);
    await expect(page.getByRole("region", { name: "OpenVPN client credentials" }).getByRole("alert")).toHaveText(
      status === 400 ? "invalid client name" : "client name already issued",
    );
    await expect(page.getByRole("textbox", { name: "Client name" })).toHaveValue("operator");
  });
}

test("downloads an active profile by ID with a readable browser filename", async ({ page }) => {
  const server = await openClients(page);
  const download = page.waitForEvent("download");
  await row(page).getByRole("button", { name: "Download", exact: true }).click();
  expect((await download).suggestedFilename()).toBe("operator.ovpn");
  expect(server.downloads).toEqual([active.id]);
  expect(server.writes).toEqual([]);
});

test("download displays the API's conflict error", async ({ page }) => {
  const server = await openClients(page);
  server.downloadStatus = 409;
  await row(page).getByRole("button", { name: "Download", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "managed server not active" })).toBeVisible();
});

test("revoked credential download is disabled", async ({ page }) => {
  const server = await openClients(page);
  await expect(row(page, revoked.name).getByRole("button", { name: "Download", exact: true })).toBeDisabled();
  expect(server.downloads).toEqual([]);
});

test("an already revoked credential can confirm runtime application after reopening", async ({ page }) => {
  const server = await openClients(page);
  await row(page, revoked.name).getByRole("button", { name: "Apply revocation", exact: true }).click();
  await page.getByRole("dialog", { name: "Apply revocation?" }).getByRole("button", { name: "Apply revocation", exact: true }).click();
  await expect(page.getByText("Client revoked and applied", { exact: true })).toBeVisible();
  expect(server.writes.map((w) => decodeURIComponent(w.path))).toEqual([`${prefix}/${revoked.id}/revoke`]);
  await expect(row(page, revoked.name).getByRole("button", { name: "Download", exact: true })).toBeDisabled();
});

test("revoke confirmation can be cancelled", async ({ page }) => {
  const server = await openClients(page);
  await row(page).getByRole("button", { name: "Revoke", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Cancel", exact: true }).click();
  expect(server.writes).toEqual([]);
  await expect(row(page).getByRole("button", { name: "Download", exact: true })).toBeEnabled();
});

test("revoke success updates the credential and disables download", async ({ page }) => {
  const server = await openClients(page);
  await confirmRevoke(page);
  await expect(row(page)).toContainText("revoked");
  await expect(row(page).getByRole("button", { name: "Download", exact: true })).toBeDisabled();
  await expect(page.getByText("Client revoked and applied", { exact: true })).toBeVisible();
  expect(server.writes.map((w) => decodeURIComponent(w.path))).toEqual([`${prefix}/${active.id}/revoke`]);
});

test("503 preserves durable revocation, warns distinctly, and allows idempotent retry", async ({ page }) => {
  const server = await openClients(page);
  server.revokeStatus = 503;
  await confirmRevoke(page);
  await expect(row(page).getByRole("status")).toContainText("Revoked, not yet applied: revoked, runtime not confirmed");
  await expect(row(page).getByRole("button", { name: "Download", exact: true })).toBeDisabled();
  await expect(page.getByText("Client revoked and applied", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(row(page).getByRole("status")).toContainText("Revoked, not yet applied");
  server.revokeStatus = 200;
  await row(page).getByRole("button", { name: "Retry apply", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Retry apply", exact: true }).click();
  await expect(row(page).getByRole("status")).toHaveCount(0);
  await expect(page.getByText("Client revoked and applied", { exact: true })).toBeVisible();
});

test("unknown credential failure does not claim durable revocation", async ({ page }) => {
  const server = await openClients(page);
  server.revokeStatus = 404;
  await confirmRevoke(page);
  await expect(page.getByRole("region", { name: "OpenVPN client credentials" }).getByRole("alert")).toHaveText("unknown credential ID");
  await expect(row(page).getByRole("button", { name: "Download", exact: true })).toBeEnabled();
  await expect(row(page).getByRole("status")).toHaveCount(0);
});

test("plain 503 is a failure, not a durable revocation", async ({ page }) => {
  const server = await openClients(page);
  server.revokeStatus = 503;
  server.revokeDurable = false;
  await confirmRevoke(page);
  await expect(page.getByRole("region", { name: "OpenVPN client credentials" }).getByRole("alert")).toHaveText("credential authority unavailable");
  await expect(row(page).getByRole("button", { name: "Download", exact: true })).toBeEnabled();
  await expect(row(page).getByRole("status")).toHaveCount(0);
});

test("failed inventory refresh preserves entries without claiming an empty list", async ({ page }) => {
  const server = await openClients(page);
  server.listStatus = 503;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Credential inventory unavailable" })).toBeVisible();
  await expect(row(page)).toContainText(active.id);
  await expect(page.getByText("No client credentials yet.")).toHaveCount(0);
});

for (const applied of [false, true]) {
  test(`reload reports revocationsApplied=${applied} without inventing pending state`, async ({ page }) => {
    const server = await openClients(page, applied);
    await page.reload();
    const region = page.getByRole("region", { name: "OpenVPN client credentials" });
    await expect(row(page, revoked.name)).toContainText("revoked");
    await expect(region.getByText("Revoked, but the running server has not reloaded the revocation list.", { exact: true })).toHaveCount(applied ? 0 : 1);
    await expect(row(page, revoked.name).getByRole("button", { name: "Apply revocation", exact: true })).toHaveCount(applied ? 0 : 1);
    expect(server.writes).toEqual([]);
  });
}

test("a cumulative restart clears all pending retries and remains applied after reload", async ({ page }) => {
  const server = await openClients(page);
  server.revokeStatus = 503;
  await confirmRevoke(page);
  await expect(row(page).getByRole("button", { name: "Retry apply", exact: true })).toBeVisible();
  server.revokeStatus = 200;
  await row(page, revoked.name).getByRole("button", { name: "Apply revocation", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Apply revocation", exact: true }).click();
  await expect(row(page).getByRole("status")).toHaveCount(0);
  await expect(page.getByRole("button", { name: /^(Retry apply|Apply revocation)$/ })).toHaveCount(0);
  await page.reload();
  await expect(row(page)).toContainText("revoked");
  await expect(page.getByRole("button", { name: /^(Retry apply|Apply revocation)$/ })).toHaveCount(0);
});

test("refresh clears pending retries when another apply has loaded the CRL", async ({ page }) => {
  const server = await openClients(page);
  server.revokeStatus = 503;
  await confirmRevoke(page);
  await expect(row(page).getByRole("button", { name: "Retry apply", exact: true })).toBeVisible();
  server.revocationsApplied = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(row(page).getByRole("status")).toHaveCount(0);
  await expect(page.getByRole("button", { name: /^(Retry apply|Apply revocation)$/ })).toHaveCount(0);
});
