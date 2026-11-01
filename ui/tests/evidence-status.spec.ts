import { expect, test, type Page } from "@playwright/test";

async function mock(page: Page, state: string, unavailable = false) {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (unavailable && (path.endsWith("/health") || path.endsWith("/evidence/status"))) {
      await route.fulfill({ status: 503, json: { error: "unavailable" } });
      return;
    }
    const json = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin", username: "containd", role: "admin" }
      : path.endsWith("/health") ? { status: "ok", evidence: { state } }
        : path.endsWith("/evidence/status") ? {
          audit: { state, failures: state === "degraded" || state === "recovered" ? 2 : 0,
            lastFailureAt: state === "degraded" || state === "recovered" ? "2026-10-31T10:00:00Z" : undefined,
            lastSuccessAt: state === "recovered" ? "2026-10-31T10:01:00Z" : undefined,
            lastError: state === "degraded" ? "audit persistence unavailable" : undefined },
          forwarding: [],
        }
          : path.endsWith("/audit") ? []
            : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json });
  });
}

for (const state of ["degraded", "unknown", "recovered", "ok"]) {
  test(`evidence ${state} is visible independently of collectors`, async ({ page }) => {
    await mock(page, state);
    const loaded = page.waitForResponse((r) => new URL(r.url()).pathname.endsWith("/evidence/status"));
    await page.goto("/audit/");
    await loaded;
    const persistence = page.getByRole("region", { name: "Audit persistence", exact: true });
    await expect(persistence).toContainText(`Audit persistence: ${state}`);
    await expect(persistence).toContainText(`Failed writes since process start: ${state === "degraded" || state === "recovered" ? 2 : 0}`);
    await expect(page.getByText(/Only successfully persisted actions/)).toBeVisible();
    const banner = page.getByRole("status", { name: "Evidence health" });
    if (state === "ok") {
      await expect(banner).toHaveCount(0);
    } else {
      await expect(banner).toContainText(state === "degraded" ? "Evidence degraded"
        : state === "recovered" ? "Evidence recovered" : "Evidence state unknown");
      await expect(banner).toHaveClass(state === "degraded" ? /text-rose-300/ : /text-amber/);
    }
    if (state === "recovered") await expect(persistence).toContainText("previously missing records are not restored");
  });
}

test("an unavailable evidence report is unknown, not a verified empty audit history", async ({ page }) => {
  await mock(page, "ok", true);
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname.endsWith("/evidence/status"));
  await page.goto("/audit/");
  await loaded;
  await expect(page.getByRole("status", { name: "Evidence health" })).toContainText("Evidence state unknown");
  await expect(page.getByRole("region", { name: "Audit persistence", exact: true })).toContainText("Persistence could not be verified");
});

test("audit failure appears in the shell without visiting Syslog or Audit", async ({ page }) => {
  await mock(page, "degraded");
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname.endsWith("/health"));
  await page.goto("/events/");
  await loaded;
  await expect(page.getByRole("status", { name: "Evidence health" })).toContainText("Operations continue");
});
