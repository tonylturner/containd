import { expect, test, type Page } from "@playwright/test";

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };

async function mockAPI(page: Page, routes: Record<string, { status?: number; json: unknown }>) {
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

async function uploadCA(page: Page) {
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/system/tls");
  await page.goto("/system/settings/");
  await loaded;
  const card = page.locator("section").filter({ hasText: "Trusted CAs (outbound)" });
  await card.locator('input[type="file"]').setInputFiles({
    name: "ca.pem", mimeType: "application/x-pem-file", buffer: Buffer.from("-----BEGIN CERTIFICATE-----\n"),
  });
  await card.getByRole("button", { name: "Upload CA bundle" }).click();
}

test("trusted CA upload reports the revision the engine applied", async ({ page }) => {
  await mockAPI(page, {
    "/api/v1/system/tls": { json: { httpEnabled: true, httpsEnabled: true } },
    "/api/v1/system/tls/trusted-ca": { json: { status: "updated", revision: "sha256:abc123" } },
  });
  await uploadCA(page);
  await expect(page.getByText("Trusted CA bundle applied by the engine (revision sha256:abc123).")).toBeVisible();
});

test("trusted CA stored but not applied is not reported as applied", async ({ page }) => {
  await mockAPI(page, {
    "/api/v1/system/tls": { json: { httpEnabled: true, httpsEnabled: true } },
    "/api/v1/system/tls/trusted-ca": {
      json: { status: "stored", revision: "sha256:abc123", warnings: ["trust: engine unavailable"] },
    },
  });
  await uploadCA(page);
  await expect(
    page.getByRole("status").filter({
      hasText: "stored (revision sha256:abc123), but the engine did not apply it: trust: engine unavailable",
    }),
  ).toBeVisible();
  await expect(page.getByText(/applied by the engine \(revision/)).toHaveCount(0);
});

test("trusted CA upload without a config store is an error, not stored", async ({ page }) => {
  await mockAPI(page, {
    "/api/v1/system/tls": { json: { httpEnabled: true, httpsEnabled: true } },
    "/api/v1/system/tls/trusted-ca": { status: 503, json: { error: "config store unavailable" } },
  });
  await uploadCA(page);
  await expect(page.getByText("config store unavailable")).toBeVisible();
  await expect(page.getByText(/Trusted CA bundle (stored|applied)/)).toHaveCount(0);
});

// A reachable engine's antivirus status carries its scan meter.
async function openServices(page: Page, av: Record<string, unknown>, sparkline: number[]) {
  const meter = {
    sparkline, count: sparkline.reduce((a, b) => a + b, 0), rate_per_min: 0,
    errors_sparkline: [], errors_count: 0, errors_rate_per_min: 0,
  };
  await mockAPI(page, { "/api/v1/services/status": { json: { av: { available: true, ...meter, ...av } } } });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/services/status");
  await page.goto("/system/services/");
  await loaded;
  await expect(page.getByText("AV scanning", { exact: true })).toBeVisible();
}

test("antivirus card shows no fabricated scan series", async ({ page }) => {
  await openServices(page, { enabled: true, mode: "clamav", clamav_custom_defs: "/data/clamav/custom" }, []);
  await expect(page.locator('[title^="AV scans"]')).toHaveCount(0);
});

test("antivirus card shows a reported scan series", async ({ page }) => {
  await openServices(page, { enabled: true, mode: "clamav" }, [1, 3, 2]);
  await expect(page.locator('[title="AV scans per minute"]')).toHaveCount(1);
});
