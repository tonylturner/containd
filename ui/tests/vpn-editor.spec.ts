import { expect, test, type Page } from "@playwright/test";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { VPNConfig } from "../lib/api-vpn";
import { observation, protectionAPI } from "./fixtures/protection-api";

const peerKey = Buffer.alloc(32, 7).toString("base64");
const serverKey = Buffer.alloc(32, 8).toString("base64");

async function vpn(page: Page, configured = true, options: { noPublicKey?: boolean; role?: "admin" | "view"; failWrite?: boolean } = {}) {
  await protectionAPI(page, observation(), { role: options.role });
  const state = {
    revision: 1,
    holdWrite: undefined as Promise<void> | undefined,
    writes: [] as { body: VPNConfig; revision: string | undefined }[],
    cfg: {
      wireguard: { enabled: true, interface: "wg0", listenPort: 51820, addressCIDR: "10.8.0.1/24", privateKeyConfigured: configured, peers: [] },
      openvpn: { enabled: true, mode: "client", managed: {
        remote: "vpn.example.test", port: 1194, proto: "udp",
        caConfigured: configured, certConfigured: configured, keyConfigured: configured, passwordConfigured: configured,
      } },
    } as VPNConfig,
  };
  await page.route("**/api/v1/services/status", route => route.fulfill({ json: { faults: [], vpn: { openvpn_running: true } } }));
  await page.route("**/api/v1/interfaces", route => route.fulfill({ json: [], headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
  await page.route("**/api/v1/services/vpn/wireguard/status?*", route => route.fulfill({
    json: { interface: "wg0", present: !options.noPublicKey, publicKey: options.noPublicKey ? undefined : serverKey, peers: [] },
  }));
  await page.route("**/api/v1/services/vpn", async route => {
    const req = route.request();
    if (req.method() !== "GET") {
      const body = req.postDataJSON() as VPNConfig;
      state.writes.push({ body, revision: req.headers()["x-containd-if-revision"] });
      if (state.holdWrite) await state.holdWrite;
      if (options.failWrite) return route.fulfill({ status: 412, json: { code: "config_revision_mismatch", error: "Configuration changed", currentRevision: "0123456789abcdef.2" } });
      const privateKeyConfigured = !!body.wireguard?.privateKey || !!state.cfg.wireguard?.privateKeyConfigured;
      const previousManaged = state.cfg.openvpn?.managed;
      state.cfg = structuredClone(body);
      delete state.cfg.wireguard?.privateKey;
      state.cfg.wireguard!.privateKeyConfigured = privateKeyConfigured;
      for (const field of ["ca", "cert", "key", "password"] as const) {
        const managed = state.cfg.openvpn?.managed;
        if (managed) {
          managed[`${field}Configured`] = !!managed[field] || !!previousManaged?.[`${field}Configured`];
          delete managed[field];
        }
      }
      state.revision++;
    }
    await route.fulfill({ json: state.cfg, headers: { "X-Containd-Revision": `0123456789abcdef.${state.revision}` } });
  });
  await Promise.all([page.waitForResponse("**/api/v1/services/vpn"), page.goto("/vpn/")]);
  if (options.role !== "view") await expect(page.getByRole("button", { name: "Save", exact: true })).toBeVisible();
  return state;
}

test("configured secrets remain blank and do not produce missing-material warnings", async ({ page }) => {
  const state = await vpn(page);
  await expect(page.getByText("Private key configured", { exact: true })).toBeVisible();
  await expect(page.getByText("Private key is required to bring up a WireGuard server.")).toHaveCount(0);
  await expect(page.getByText("CA certificate (PEM) is required.")).toHaveCount(0);
  await expect(page.getByText("Client certificate (PEM) is required.")).toHaveCount(0);
  await expect(page.getByText("Client key (PEM) is required.")).toHaveCount(0);
  await expect(page.getByLabel("CA (PEM)", { exact: true })).toHaveValue("");
  await expect(page.getByLabel("Client Key (PEM)", { exact: true })).toHaveValue("");
  await expect(page.getByLabel("OpenVPN password")).toHaveValue("");
  await page.getByRole("button", { name: "Replace", exact: true }).click();
  await expect(page.getByLabel("Private Key (base64)")).toHaveValue("");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => state.writes.length).toBe(1);
  expect(state.writes[0].revision).toBe("0123456789abcdef.1");
  expect(state.writes[0].body.wireguard?.privateKey).toBe("");
  await expect(page.getByText("VPN staged — commit to apply.", { exact: true })).toBeVisible();
});

test("unset secrets still show required setup warnings", async ({ page }) => {
  await vpn(page, false);
  await expect(page.getByText("Private key is required to bring up a WireGuard server.")).toBeVisible();
  await expect(page.getByText("CA certificate (PEM) is required.")).toBeVisible();
  await expect(page.getByText("Client key (PEM) is required.")).toBeVisible();
});

test("managed OpenVPN material can be replaced by file without revealing it after Save", async ({ page }) => {
  const state = await vpn(page);
  const field = page.getByLabel("Client Key (PEM)", { exact: true });
  const material = "-----BEGIN PRIVATE KEY-----\nreplacement-material\n-----END PRIVATE KEY-----";
  await field.locator("..").locator('input[type="file"]').setInputFiles({
    name: "replacement.pem", mimeType: "text/plain", buffer: Buffer.from(material),
  });
  await expect(field).toHaveValue(material);
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => state.writes[0]?.body.openvpn?.managed?.key).toBe(material);
  await expect(field).toHaveValue("");
});

for (const newerReplacement of [false, true]) {
  test(`delayed Save scrubs submitted secrets after a peer edit, newer replacement=${newerReplacement}`, async ({ page }) => {
    const state = await vpn(page);
    let release = () => {};
    state.holdWrite = new Promise<void>(resolve => { release = resolve; });
    const privateField = page.getByLabel("Private Key (base64)");
    const keyField = page.getByLabel("Client Key (PEM)", { exact: true });
    const caField = page.getByLabel("CA (PEM)", { exact: true });
    const certField = page.getByLabel("Client Cert (PEM)", { exact: true });
    const passwordField = page.getByLabel("OpenVPN password");
    const material = "-----BEGIN PRIVATE KEY-----\nsubmitted-material\n-----END PRIVATE KEY-----";
    const newerMaterial = material.replace("submitted-material", "newer-material");
    try {
      await page.getByRole("button", { name: "Replace", exact: true }).click();
      await privateField.fill("submitted-wireguard-key");
      await keyField.fill(material);
      await caField.fill(material);
      await certField.fill(material);
      await passwordField.fill("submitted-password");
      await page.getByRole("button", { name: "Save", exact: true }).click();
      await expect.poll(() => state.writes.length).toBe(1);
      await page.getByRole("button", { name: "Add peer", exact: true }).click();
      const peer = page.getByRole("group", { name: "Peer 1", exact: true });
      await peer.getByLabel("Name", { exact: true }).fill("Unsaved peer");
      await peer.getByLabel("Public key", { exact: true }).fill(peerKey);
      if (newerReplacement) {
        await privateField.fill("newer-wireguard-key");
        await keyField.locator("..").locator('input[type="file"]').setInputFiles({
          name: "newer.pem", mimeType: "text/plain", buffer: Buffer.from(newerMaterial),
        });
        await expect(keyField).toHaveValue(newerMaterial);
      }
      release();
      await expect(page.getByText("VPN staged — commit to apply.", { exact: true })).toBeVisible();
      await expect(privateField).toHaveValue(newerReplacement ? "newer-wireguard-key" : "");
      await expect(keyField).toHaveValue(newerReplacement ? newerMaterial : "");
      await expect(caField).toHaveValue("");
      await expect(certField).toHaveValue("");
      await expect(passwordField).toHaveValue("");
      await expect(page.getByText("Private key configured", { exact: true })).toBeVisible();
      await expect(peer.getByLabel("Name", { exact: true })).toHaveValue("Unsaved peer");
      state.holdWrite = undefined;
      await page.getByRole("button", { name: "Save", exact: true }).click();
      await expect.poll(() => state.writes.length).toBe(2);
      expect(state.writes[1].body.wireguard).toMatchObject({
        privateKey: newerReplacement ? "newer-wireguard-key" : "",
        peers: [{ name: "Unsaved peer", publicKey: peerKey, allowedIPs: [] }],
      });
      expect(state.writes[1].body.openvpn?.managed).toMatchObject({
        key: newerReplacement ? newerMaterial : "", ca: "", cert: "", password: "",
      });
      await expect(privateField).toHaveValue("");
      await expect(keyField).toHaveValue("");
    } finally { release(); }
  });
}

test("peer rows and Advanced JSON share a revision-protected round trip at 390px", async ({ page }) => {
  const state = await vpn(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Add peer", exact: true }).click();
  const peer = page.getByRole("group", { name: "Peer 1", exact: true });
  await peer.getByLabel("Name", { exact: true }).fill("Operator");
  await peer.getByLabel("Public key", { exact: true }).fill(peerKey);
  await peer.getByLabel("Allowed IPs (comma-separated CIDRs)", { exact: true }).fill("10.8.0.2/32, 192.0.2.0/24");
  await peer.getByLabel("Endpoint (optional host:port)", { exact: true }).fill("client.example.test:51820");
  await peer.getByLabel("Keepalive (seconds)", { exact: true }).fill("30");
  const json = page.getByRole("textbox", { name: "Peers (JSON)", exact: true });
  const peers = [{ name: "Operator", publicKey: peerKey, allowedIPs: ["10.8.0.2/32", "192.0.2.0/24"], endpoint: "client.example.test:51820", persistentKeepalive: 30 }];
  await expect(json).toHaveValue(JSON.stringify(peers, null, 2));
  peers[0].name = "Engineer";
  await json.fill(JSON.stringify(peers));
  await expect(peer.getByLabel("Name", { exact: true })).toHaveValue("Engineer");
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await expect(peer.getByRole("button", { name: "Remove peer" })).toBeVisible();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => state.writes[0]?.body.wireguard?.peers).toEqual(peers);
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(peer.getByLabel("Name", { exact: true })).toHaveValue("Engineer");
  await peer.getByRole("button", { name: "Remove peer" }).click();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => state.writes[1]?.body.wireguard?.peers).toEqual([]);
});

test("browser X25519 generation stages only a private key and clears it after Save", async ({ page }) => {
  const state = await vpn(page, false, { noPublicKey: true });
  await page.getByRole("button", { name: "Generate key pair", exact: true }).click();
  const privateField = page.getByLabel("Private Key (base64)");
  await expect(privateField).toHaveValue(/^[A-Za-z0-9+/]{43}=$/);
  const key = await privateField.inputValue();
  expect(Buffer.from(key, "base64")).toHaveLength(32);
  await page.getByRole("button", { name: "Add peer", exact: true }).click();
  await page.getByRole("group", { name: "Peer 1", exact: true }).getByLabel("Public key", { exact: true }).fill(peerKey);
  await page.getByLabel("Server endpoint for client downloads (host:port)").fill("vpn.example.test:51820");
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download client config", exact: true }).click();
  const download = await downloadPromise;
  const content = await readFile((await download.path())!, "utf8");
  const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), Buffer.from(key, "base64")]), format: "der", type: "pkcs8" });
  const publicKey = createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
  expect(content).toContain(`PublicKey = ${publicKey}`);
  expect(content).toContain("PrivateKey = REPLACE_WITH_CLIENT_PRIVATE_KEY");
  expect(content).not.toContain(key);
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => state.writes.length).toBe(1);
  expect(state.writes[0].body.wireguard?.privateKey).toBe(key);
  expect(state.writes[0].body.wireguard).not.toHaveProperty("publicKey");
  await expect(privateField).toHaveCount(0);
  expect(await page.evaluate(k => JSON.stringify({ ...localStorage, ...sessionStorage }).includes(k), key)).toBe(false);
});

test("unsupported WebCrypto hides key generation and explains the alternative", async ({ page }) => {
  await page.addInitScript(() => Object.defineProperty(window.crypto, "subtle", { value: undefined }));
  await vpn(page);
  await expect(page.getByText(/Key generation unavailable: this browser/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Generate key pair", exact: true })).toHaveCount(0);
});

test("download is omitted until server public key and endpoint are known", async ({ page }) => {
  await vpn(page);
  await page.getByRole("button", { name: "Add peer", exact: true }).click();
  await page.getByRole("group", { name: "Peer 1", exact: true }).getByLabel("Public key", { exact: true }).fill(peerKey);
  await expect(page.getByRole("button", { name: "Download client config" })).toHaveCount(0);
  await expect(page.getByText(/Client download unavailable: enter a valid server endpoint/)).toBeVisible();
  await page.getByLabel("Server endpoint for client downloads (host:port)").fill("vpn.example.test:51820");
  const pending = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download client config" }).click();
  const download = await pending;
  const content = await readFile((await download.path())!, "utf8");
  expect(content).toContain(`PublicKey = ${serverKey}`);
  expect(content).toContain("Endpoint = vpn.example.test:51820");
});

test("missing live public key prevents downloads even with an endpoint", async ({ page }) => {
  await vpn(page, true, { noPublicKey: true });
  await page.getByLabel("Server endpoint for client downloads (host:port)").fill("vpn.example.test:51820");
  await expect(page.getByText(/Client download unavailable: server public key is unknown/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Download client config" })).toHaveCount(0);
});

test("invalid Advanced JSON is visible and cannot stage", async ({ page }) => {
  const state = await vpn(page);
  await page.getByText("Advanced peer settings", { exact: true }).click();
  await page.getByRole("textbox", { name: "Peers (JSON)", exact: true }).fill('[{"publicKey":7}]');
  await expect(page.getByRole("alert").filter({ hasText: /Peers must be a JSON array/ })).toBeVisible();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  expect(state.writes).toEqual([]);
});

test("invalid peer values remain editable and are not silently normalized on Save", async ({ page }) => {
  const state = await vpn(page);
  await page.getByRole("button", { name: "Add peer" }).click();
  const peer = page.getByRole("group", { name: "Peer 1", exact: true });
  await peer.getByLabel("Public key", { exact: true }).fill(peerKey);
  await peer.getByLabel("Keepalive (seconds)").fill("-1");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("Peer keepalive must be a nonnegative whole number of seconds.")).toBeVisible();
  await peer.getByLabel("Keepalive (seconds)").fill("25");
  await peer.getByLabel("Allowed IPs (comma-separated CIDRs)").fill("10.8.0.2/32,");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("Peer allowed IPs cannot include empty entries.")).toBeVisible();
  expect(state.writes).toEqual([]);
  await peer.getByLabel("Allowed IPs (comma-separated CIDRs)").fill("");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => state.writes[0]?.body.wireguard?.peers?.[0]).toMatchObject({ allowedIPs: [], persistentKeepalive: 25 });
});

test("a revision conflict preserves the replacement secret for review", async ({ page }) => {
  const state = await vpn(page, false, { failWrite: true });
  await page.getByLabel("Private Key (base64)").fill("replacement");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("Configuration changed since you loaded it")).toBeVisible();
  await expect(page.getByLabel("Private Key (base64)")).toHaveValue("replacement");
  expect(state.writes).toHaveLength(1);
});

test("view-only operators cannot edit peers or replace secrets", async ({ page }) => {
  const state = await vpn(page, true, { role: "view" });
  await expect(page.getByRole("button", { name: "Add peer" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Replace", exact: true })).toBeDisabled();
  expect(state.writes).toEqual([]);
});

test("OpenVPN credential creation is confirmed and independent of staged Save", async ({ page }) => {
  const state = await vpn(page);
  state.cfg.openvpn = { enabled: true, mode: "server", server: { listenPort: 1194, proto: "udp", tunnelCIDR: "10.9.0.0/24", publicEndpoint: "vpn.example.test" } };
  const actions: unknown[] = [];
  await page.route("**/api/v1/services/vpn/openvpn/clients", async route => {
    if (route.request().method() === "GET") return route.fulfill({ json: { clients: [], revocationsApplied: true } });
    actions.push(route.request().postDataJSON());
    await route.fulfill({ json: { id: "issued", name: "Operator", serial: "1", issuer: "test", issuedAt: "2026-11-01T00:00:00Z", expiresAt: "2027-11-01T00:00:00Z" } });
  });
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await page.getByRole("textbox", { name: "Client name", exact: true }).fill("Operator");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("independent of Save");
  expect(actions).toEqual([]);
  await dialog.getByRole("button", { name: "Create", exact: true }).click();
  await expect.poll(() => actions).toEqual([{ name: "Operator" }]);
  expect(state.writes).toEqual([]);
});
