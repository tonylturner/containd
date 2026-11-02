import { expect, test, type Page } from "@playwright/test";
import { observation, protectionAPI } from "./fixtures/protection-api";

const revision = "0123456789abcdef.1";
async function setup(page: Page, role: "admin" | "view" = "admin") {
  await protectionAPI(page, observation(), { role });
  const cfg = { system: { hostname: "appliance", mgmt: { listenAddr: ":8080" }, ssh: {} }, future: { keep: true } };
  const state = { writes: [] as { path: string; body: any; revision?: string }[], unavailable: false, reject: "", candidateReject: "", conflict: false };
  await page.route("**/api/v1/config/candidate", async route => {
    if (route.request().method() === "GET") return route.fulfill({ status: state.unavailable ? 503 : 200, json: state.unavailable ? { error: "offline" } : cfg, headers: { "X-Containd-Revision": revision } });
    state.writes.push({ path: "candidate", body: route.request().postDataJSON(), revision: route.request().headers()["x-containd-if-revision"] });
    return route.fulfill({ status: state.conflict ? 412 : state.candidateReject ? 400 : 200, json: state.candidateReject ? { error: state.candidateReject } : state.conflict ? { error: "revision conflict", code: "config_revision_mismatch", currentRevision: "0123456789abcdef.2" } : { status: "staged" }, headers: { "X-Containd-Revision": state.conflict ? "0123456789abcdef.2" : revision } });
  });
  await page.route("**/api/v1/config/validate", async route => {
    state.writes.push({ path: "validate", body: route.request().postDataJSON() });
    return route.fulfill({ status: state.reject ? 400 : 200, json: state.reject ? { error: state.reject } : { status: "valid" } });
  });
  return state;
}

test("management settings stage all fields losslessly, with revision and no commit", async ({ page }) => {
  const state = await setup(page);
  await page.goto("/system/settings/");
  await expect(page.getByLabel("Hostname", { exact: true })).toHaveValue("appliance");
  await expect(page.getByRole("combobox", { name: "HTTP access", exact: true })).toHaveValue("");
  const text = {
    Hostname: "station", "HTTP listen address": ":8088", "HTTPS listen address": ":8444",
    "TLS certificate path": "/data/server.pem", "TLS private key path": "/data/server.key",
    "Trusted CA path": "/data/ca.pem", "SSH listen address": ":2223",
    "Authorized keys directory": "/data/keys", "SSH banner": "Authorized operators only",
    "Host key rotation (days; 0 disables)": "45", "HSTS max age (seconds)": "600",
  };
  for (const [label, value] of Object.entries(text)) await page.getByLabel(label, { exact: true }).fill(value);
  for (const label of ["HTTP access", "HTTPS access", "Redirect HTTP to HTTPS", "HSTS", "SSH password authentication"]) {
    await page.getByRole("combobox", { name: label, exact: true }).selectOption("true");
  }
  await page.getByRole("combobox", { name: "SSH shell mode", exact: true }).selectOption("linux");
  await page.getByRole("button", { name: "Save management access", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "Management access staged" })).toBeVisible();
  expect(state.writes.map(w => w.path)).toEqual(["validate", "candidate"]);
  expect(state.writes[1].revision).toBe(revision);
  expect(state.writes[1].body).toEqual({ future: { keep: true }, system: {
    hostname: "station", mgmt: { listenAddr: "", httpListenAddr: ":8088", httpsListenAddr: ":8444", tlsCertFile: "/data/server.pem", tlsKeyFile: "/data/server.key", trustedCAFile: "/data/ca.pem", enableHTTP: true, enableHTTPS: true, redirectHTTPToHTTPS: true, enableHSTS: true, hstsMaxAgeSeconds: 600 },
    ssh: { listenAddr: ":2223", authorizedKeysDir: "/data/keys", banner: "Authorized operators only", hostKeyRotationDays: 45, allowPassword: true, shellMode: "linux" },
  } });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

for (const refusal of ["reserved management HTTP cannot be disabled", "SSH password disable requires enrolled administrator key"]) {
  test(`management form preserves edits on server safety refusal: ${refusal}`, async ({ page }) => {
    const state = await setup(page);
    const keyRefusal = refusal.startsWith("SSH");
    if (keyRefusal) state.candidateReject = refusal;
    else state.reject = refusal;
    await page.goto("/system/settings/");
    await expect(page.getByLabel("Hostname", { exact: true })).toHaveValue("appliance");
    await page.getByRole("combobox", { name: "SSH password authentication", exact: true }).selectOption("false");
    await page.getByRole("button", { name: "Save management access", exact: true }).click();
    await expect(page.getByRole("alert").filter({ hasText: refusal })).toBeVisible();
    await expect(page.getByRole("combobox", { name: "SSH password authentication", exact: true })).toHaveValue("false");
    expect(state.writes.map(w => w.path)).toEqual(keyRefusal ? ["validate", "candidate"] : ["validate"]);
  });
}

test("stale management writes do not retry or lose edits", async ({ page }) => {
  const state = await setup(page);
  state.conflict = true;
  await page.goto("/system/settings/");
  await expect(page.getByLabel("Hostname", { exact: true })).toHaveValue("appliance");
  await page.getByLabel("Hostname", { exact: true }).fill("draft");
  await page.getByRole("button", { name: "Save management access", exact: true }).click();
  await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Hostname", { exact: true })).toHaveValue("draft");
  expect(state.writes.filter(w => w.path === "candidate")).toHaveLength(1);
});

test("unavailable candidate disables management edits without inventing defaults", async ({ page }) => {
  const state = await setup(page);
  state.unavailable = true;
  await page.goto("/system/settings/");
  await expect(page.getByRole("alert").filter({ hasText: "Management configuration unavailable" })).toBeVisible();
  await expect(page.getByLabel("Hostname", { exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Save management access", exact: true })).toBeDisabled();
  expect(state.writes).toEqual([]);
});

test("view-only settings cannot stage or clear trust", async ({ page }) => {
  const state = await setup(page, "view");
  await page.goto("/system/settings/");
  await expect(page.getByRole("heading", { name: "Permission denied", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Save management access", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Clear", exact: true })).toHaveCount(0);
  expect(state.writes).toEqual([]);
});

for (const status of ["updated", "stored", "failed"]) {
  test(`CA clear is confirmed and reports ${status} truthfully`, async ({ page }) => {
    await setup(page);
    const bodies: unknown[] = [];
    await page.route("**/api/v1/system/tls/trusted-ca", async route => {
      bodies.push(route.request().postDataJSON());
      return route.fulfill({ status: status === "failed" ? 400 : 200, json: status === "failed" ? { error: "trust update refused" } : { status, revision: "none", warnings: status === "stored" ? ["engine unreachable"] : [] } });
    });
    await page.goto("/system/settings/");
    await page.getByRole("button", { name: "Clear", exact: true }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toContainText("Outbound TLS to private ICAP servers or definition sources may fail");
    expect(bodies).toEqual([]);
    await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
    expect(bodies).toEqual([]);
    await page.getByRole("button", { name: "Clear", exact: true }).click();
    await dialog.getByRole("button", { name: "Clear", exact: true }).click();
    await expect.poll(() => bodies.length).toBe(1);
    expect(bodies).toEqual([{ clear: true }]);
    await expect(page.getByText(status === "updated" ? "Additional trust cleared. Outbound TLS now uses the OS trust store." : status === "stored" ? "Trust certificates saved but not active. Applying configuration retries activation: engine unreachable" : "trust update refused", { exact: true })).toBeVisible();
  });
}
