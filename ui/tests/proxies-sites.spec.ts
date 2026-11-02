import { expect, test, type Page } from "@playwright/test";
import type { ReverseProxyConfig, ReverseProxySite } from "../lib/api";

const revision = "0123456789abcdef.1";
const nextRevision = "0123456789abcdef.2";
const site: ReverseProxySite = {
  name: "plant", listenPort: 8081, hostnames: ["plant.example"], backends: ["plc:80", "backup:80"],
  tlsEnabled: false, description: "Existing application",
};
const otherSite: ReverseProxySite = { name: "other", listenPort: 8082, backends: ["other:80"] };
const meter = { sparkline: [], count: 0, rate_per_min: 0, errors_sparkline: [], errors_count: 0, errors_rate_per_min: 0 };
const status = { faults: [], av: { available: false, error: "unavailable" },
  proxy: { ...meter, envoy_running: false, nginx_running: false }, envoy: meter, nginx: meter };

async function mockAPI(page: Page, options: {
  sites?: ReverseProxySite[]; role?: string; conflict?: boolean; live?: unknown;
} = {}) {
  let currentRevision = revision;
  let reverse: ReverseProxyConfig = { enabled: true, sites: options.sites ?? [site, otherSite] };
  const writes: { path: string; body: ReverseProxyConfig; revision: string | undefined }[] = [];
  const role = options.role ?? "admin";
  await page.addInitScript(role => {
    localStorage.setItem("containd.auth.role", role);
    localStorage.setItem("containd.auth.token", "test-token");
  }, role);
  await page.route("**/api/v1/**", async route => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace("/api/v1", "");
    if (request.method() !== "GET") {
      const body = request.postDataJSON();
      writes.push({ path, body, revision: request.headers()["x-containd-if-revision"] });
      if (options.conflict) return route.fulfill({ status: 412,
        json: { code: "config_revision_mismatch", error: "stale", currentRevision: nextRevision } });
      reverse = body;
      currentRevision = `${currentRevision.split(".")[0]}.${Number(currentRevision.split(".")[1]) + 1}`;
    }
    const data = path.startsWith("/auth/") ? { id: "user", username: "containd", role }
      : path === "/services/status" ? options.live ?? status
        : path === "/services/proxy/forward" ? { enabled: false, listenPort: 3128, listenZones: ["mgmt"] }
          : path === "/services/proxy/reverse" ? reverse : {};
    await route.fulfill({ json: data, headers: { "X-Containd-Revision": currentRevision } });
  });
  return { writes, change: (sites: ReverseProxySite[]) => {
    reverse = { ...reverse, sites };
    currentRevision = nextRevision;
  } };
}

async function open(page: Page) {
  const loaded = page.waitForResponse("**/api/v1/services/proxy/reverse");
  await page.goto("/proxies/");
  await loaded;
  await expect(page.getByRole("heading", { name: "Add site", exact: true })).toBeVisible();
}

function reverseSection(page: Page) {
  return page.locator("section").filter({ has: page.getByRole("heading", { name: "Reverse proxy", exact: true }) }).first();
}

test("editing a site stages TLS, certificate reference and description without replacing other sites", async ({ page }) => {
  const server = await mockAPI(page);
  await open(page);
  await page.getByRole("button", { name: "Edit", exact: true }).first().click();
  await expect(page.getByLabel("Site name", { exact: true })).toHaveValue("plant");
  await expect(page.getByLabel("Backends", { exact: true })).toHaveValue("plc:80, backup:80");
  await page.getByLabel("Site name", { exact: true }).fill("plant_https");
  await page.getByLabel("Listen port", { exact: true }).last().fill("8443");
  await page.getByLabel("Description", { exact: true }).fill("TLS application");
  await page.getByRole("button", { name: "Site TLS", exact: true }).click();
  await page.getByLabel("Enable TLS", { exact: true }).check();
  await page.getByLabel("Certificate reference", { exact: true }).fill("plant-web");
  await expect(page.getByText(/System Settings uploads the management HTTPS identity/)).toBeVisible();
  await page.getByRole("button", { name: "Update site", exact: true }).click();
  expect(server.writes).toEqual([]);
  await reverseSection(page).getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(1);
  expect(server.writes).toEqual([{ path: "/services/proxy/reverse", revision, body: { enabled: true,
    sites: [{ ...site, name: "plant_https", listenPort: 8443, tlsEnabled: true, certRef: "plant-web", description: "TLS application" }, otherSite] } }]);
  await expect(page.getByText("Reverse proxy staged — commit to apply.", { exact: true })).toBeVisible();
});

test("saved TLS fields open automatically and remain editable when disabling TLS", async ({ page }) => {
  const server = await mockAPI(page, { sites: [{ ...site, tlsEnabled: true, certRef: "existing" }] });
  await open(page);
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  await expect(page.getByRole("button", { name: "Site TLS", exact: true })).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByLabel("Certificate reference")).toHaveValue("existing");
  await page.getByLabel("Enable TLS").uncheck();
  await page.getByRole("button", { name: "Update site", exact: true }).click();
  await reverseSection(page).getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(1);
  expect(server.writes[0].body.sites).toEqual([{ ...site, tlsEnabled: false, certRef: "existing" }]);
});

test("new TLS site requires a certificate reference, then Add remains local until Save", async ({ page }) => {
  const server = await mockAPI(page, { sites: [] });
  await open(page);
  await page.getByLabel("Site name", { exact: true }).fill("new_site");
  await page.getByLabel("Backends", { exact: true }).fill("backend:80");
  await page.getByRole("button", { name: "Site TLS", exact: true }).click();
  await page.getByLabel("Enable TLS", { exact: true }).check();
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await expect(page.getByText("Certificate reference is required when TLS is enabled.")).toBeVisible();
  await expect(page.getByText("No reverse proxy sites configured.")).toBeVisible();
  await page.getByLabel("Certificate reference").fill("new-cert");
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await expect(page.getByText("new_site", { exact: true })).toBeVisible();
  expect(server.writes).toEqual([]);
  await reverseSection(page).getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(1);
  expect(server.writes[0].body.sites).toEqual([{ name: "new_site", listenPort: 8081, backends: ["backend:80"],
    hostnames: [], tlsEnabled: true, certRef: "new-cert" }]);
});

test("cancel and duplicate-name validation do not overwrite a site", async ({ page }) => {
  const server = await mockAPI(page);
  await open(page);
  await page.getByRole("button", { name: "Edit", exact: true }).first().click();
  await page.getByLabel("Site name", { exact: true }).fill("other");
  await page.getByRole("button", { name: "Update site", exact: true }).click();
  await expect(page.getByText("Site name is already in use.")).toBeVisible();
  await page.getByRole("button", { name: "Cancel edit", exact: true }).click();
  await expect(page.getByLabel("Site name", { exact: true })).toHaveValue("");
  await reverseSection(page).getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(1);
  expect(server.writes[0].body.sites).toEqual([site, otherSite]);
});

test("stale reverse-proxy writes retain site edits and require review", async ({ page }) => {
  const server = await mockAPI(page, { conflict: true });
  await open(page);
  await page.getByRole("button", { name: "Edit", exact: true }).first().click();
  await page.getByLabel("Description", { exact: true }).fill("Keep this edit");
  await page.getByRole("button", { name: "Update site", exact: true }).click();
  await reverseSection(page).getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("Configuration changed since you loaded it")).toBeVisible();
  await expect(page.getByText("Keep this edit", { exact: true })).toBeVisible();
  expect(server.writes).toHaveLength(1);
  expect(server.writes[0].revision).toBe(revision);
});

test("background refresh preserves an unfinished edit and requires review before merging it into a newer list", async ({ page }) => {
  const server = await mockAPI(page);
  await open(page);
  await page.getByRole("button", { name: "Edit", exact: true }).first().click();
  await page.getByLabel("Description", { exact: true }).fill("Unfinished edit");
  const changedOther = { ...otherSite, description: "External change" };
  server.change([site, changedOther]);
  await Promise.all([
    page.waitForResponse("**/api/v1/services/proxy/reverse"),
    page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:staged"))),
  ]);
  await expect(page.getByLabel("Description", { exact: true })).toHaveValue("Unfinished edit");
  await expect(page.getByText("External change", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Update site", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Edit site", exact: true })).toBeVisible();
  expect(server.writes).toEqual([]);
  await page.getByRole("button", { name: "Keep my edits", exact: true }).click();
  await page.getByRole("button", { name: "Update site", exact: true }).click();
  await reverseSection(page).getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(1);
  expect(server.writes[0]).toMatchObject({ revision: nextRevision,
    body: { sites: [{ ...site, description: "Unfinished edit" }, changedOther] } });
});

test("Refresh discards the edit form and a saved non-TLS certificate reference still opens Site TLS", async ({ page }) => {
  await mockAPI(page, { sites: [{ ...site, tlsEnabled: false, certRef: "reserved-cert" }] });
  await open(page);
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  await expect(page.getByRole("button", { name: "Site TLS", exact: true })).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByLabel("Certificate reference")).toHaveValue("reserved-cert");
  await page.getByLabel("Description", { exact: true }).fill("Discard this");
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Add site", exact: true })).toBeVisible();
  await expect(page.getByLabel("Site name", { exact: true })).toHaveValue("");
  await expect(page.getByLabel("Description", { exact: true })).toHaveValue("");
});

test("view-only users cannot edit or stage sites", async ({ page }) => {
  const server = await mockAPI(page, { role: "view" });
  await open(page);
  await expect(page.getByLabel("Site name", { exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Add", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Edit", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Save", exact: true })).toHaveCount(0);
  expect(server.writes).toEqual([]);
});

test("mobile fault leads with one summary and keeps raw preflight output under Technical details", async ({ page }) => {
  const raw = "envoy preflight: exit status 1: Unable to parse generated YAML\nstatic_resources:\n  " + "config_value_".repeat(80);
  await mockAPI(page, { live: { ...status, proxy: { ...status.proxy, envoy_last_error: raw } },
    sites: [{ ...site, name: "long_site_name_".repeat(4), backends: [`${"backend".repeat(25)}:80`] }] });
  await page.setViewportSize({ width: 390, height: 844 });
  await open(page);
  const strip = page.getByRole("region", { name: "Forward proxy status" });
  await expect(strip).toContainText("Generated proxy configuration failed validation");
  await expect(strip.locator("pre")).toBeHidden();
  await strip.getByText("Technical details", { exact: true }).focus();
  await page.keyboard.press("Enter");
  await expect(strip.locator("pre")).toBeVisible();
  await expect(strip.locator("pre")).toHaveText(raw);
  await expect(page.locator("pre")).toHaveCount(1);
  await page.getByRole("button", { name: "Edit", exact: true }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Edit site", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Site TLS", exact: true }).click();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
});

test("unavailable runtime stays unknown rather than stopped", async ({ page }) => {
  await mockAPI(page, { live: { faults: [], av: { available: false, error: "unavailable" } } });
  await open(page);
  for (const label of ["Forward proxy status", "Reverse proxy status"]) {
    await expect(page.getByRole("region", { name: label })).toContainText("Running: Unknown");
    await expect(page.getByRole("region", { name: label })).toContainText("Live proxy status unavailable");
  }
});

test("certificate validity faults retain their cause above the exact diagnostic output", async ({ page }) => {
  const fault = { service: "proxy", kind: "config", message: "site plant TLS: certificate is not currently valid" };
  await mockAPI(page, { live: { ...status, faults: [fault], proxy: { ...status.proxy, state: "faulted", fault } } });
  await open(page);
  const strip = page.getByRole("region", { name: "Reverse proxy status" });
  await expect(strip).toContainText("Proxy TLS certificate is expired or not yet valid");
  await expect(strip.locator("pre")).toBeHidden();
  await strip.getByText("Technical details", { exact: true }).click();
  await expect(strip.locator("pre")).toHaveText(fault.message);
});
