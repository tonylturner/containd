import { expect, test, type Page } from "@playwright/test";
import { observation, protectionAPI } from "./fixtures/protection-api";

async function review(page: Page, deadline: string | null = null) {
  const mock = await protectionAPI(page, observation());
  const diff = {
    changed: true, changedSections: ["system", "services"],
    running: { system: { hostname: "before" }, services: { vpn: { privateKey: "" } } },
    candidate: { system: { hostname: "after" }, services: { vpn: { privateKey: "" } } },
    pendingConfirm: deadline ? { deadline } : null,
  };
  await page.route("**/api/v1/config/diff", route => route.fulfill({
    json: diff, headers: { "X-Containd-Revision": "0123456789abcdef.1" },
  }));
  await page.route("**/api/v1/config/backups", route => route.fulfill({ json: [] }));
  await page.goto("/config/?tab=diff");
  await expect(page.getByRole("region", { name: "System changes", exact: true })).toBeVisible();
  return { mock, diff };
}

test("review leads with entity summaries and secret-only changes; exact values open by keyboard", async ({ page }) => {
  await review(page);
  const summary = page.getByRole("region", { name: "System changes", exact: true });
  await expect(summary).toContainText("System / hostname changed");
  await expect(summary.locator('[aria-label="Old value"]')).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Services changes", exact: true })).toHaveText(/Secret values changed \(hidden\)/);
  const advanced = page.getByRole("button", { name: "Advanced", exact: true });
  await expect(advanced).toHaveAttribute("aria-expanded", "false");
  await expect(page.getByRole("region", { name: "System JSON changes", exact: true })).not.toBeVisible();
  await advanced.focus();
  await page.keyboard.press("Enter");
  await expect(advanced).toBeFocused();
  await expect(advanced).toHaveAttribute("aria-expanded", "true");
  const fields = page.getByRole("region", { name: "System field changes", exact: true });
  await expect(fields).toContainText("system.hostname");
  await expect(fields.locator('[aria-label="Old value"]')).toHaveText('"before"');
  await expect(fields.locator('[aria-label="New value"]')).toHaveText('"after"');
  const raw = page.getByRole("region", { name: "System JSON changes", exact: true });
  await expect(raw).toContainText('"hostname": "before"');
  await expect(raw).toContainText('"hostname": "after"');
  await expect(page.getByRole("region", { name: "Services JSON changes", exact: true })).not.toContainText("privateKey");
  await page.keyboard.press("Space");
  await expect(advanced).toHaveAttribute("aria-expanded", "false");
  await expect(advanced).toBeFocused();
  await expect(page.getByRole("button", { name: "Commit", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Commit-confirmed", exact: true })).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Commit-confirmed seconds" })).toHaveValue("60");
  for (const width of [1280, 390]) {
    await page.setViewportSize({ width, height: 900 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  }
});

test("Confirm is prominent only for a pending deadline; Rollback warns that candidate is kept", async ({ page }) => {
  const deadline = new Date(Date.now() + 120_000).toISOString();
  const { diff } = await review(page, deadline);
  const pending = page.getByRole("region", { name: "Pending confirmation", exact: true });
  await expect(pending.locator("time")).toHaveAttribute("datetime", deadline);
  await expect(pending.getByRole("button", { name: "Confirm", exact: true })).toBeEnabled();
  const recovery = page.getByRole("button", { name: "Recovery", exact: true });
  await expect(recovery).toHaveAttribute("aria-expanded", "false");
  await recovery.click();
  await expect(page.getByText(/Rollback restores the previous committed configuration while keeping the newer staged candidate/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Rollback", exact: true })).toBeEnabled();
  diff.pendingConfirm = null;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(pending).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Confirm", exact: true })).toBeVisible();
  await recovery.click();
  await expect(page.getByRole("button", { name: "Confirm", exact: true })).not.toBeVisible();
});

test("one attention area keeps failed, unknown, healthy and unavailable domains independent", async ({ page }) => {
  await protectionAPI(page, observation({
    state: "failed", retryable: true,
    components: [{ name: "nft", state: "failed", required: true, reason: "policy install refused", since: "2026-11-01T12:00:00Z" }],
    effects: [{ traffic: "Forwarded traffic", effect: "unknown" }],
  }));
  await page.route("**/api/v1/health", route => route.fulfill({ json: {
    status: "ok", managementRecovery: { state: "unknown", reason: "startup observation unavailable" }, evidence: { state: "ok" },
  } }));
  await page.route("**/api/v1/config/diff", route => route.fulfill({ status: 404, json: { error: "endpoint missing" } }));
  await page.goto("/config/");
  const attention = page.getByRole("region", { name: "Attention", exact: true });
  const protection = attention.getByRole("status", { name: "Traffic protection", exact: true });
  await expect(protection.getByText("nft: policy install refused", { exact: true })).toBeVisible();
  await expect(protection.getByRole("button", { name: "Retry protection" })).toBeVisible();
  await expect(attention.getByRole("status", { name: "Boot recovery" })).toContainText("Boot recovery state unknown");
  await expect(attention.getByText("startup observation unavailable", { exact: true })).toBeVisible();
  await expect(attention.getByRole("link", { name: "Interfaces", exact: true })).toHaveAttribute("href", "/interfaces/");
  await expect(attention.getByRole("status", { name: "Evidence health" })).toHaveCount(0);
  await expect(attention.getByRole("status", { name: "Pending settings" })).toContainText("Configuration status unknown");
  await protection.getByRole("button", { name: "Technical details" }).click();
  await expect(protection.locator("time")).toHaveAttribute("datetime", "2026-10-31T12:00:00Z");
  await expect(protection.getByText(/Boot ID: boot-a/)).toBeVisible();
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(protection.getByText("nft: policy install refused", { exact: true })).toBeVisible();
  for (const width of [1280, 390]) {
    await page.setViewportSize({ width, height: 900 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  }
});

test("healthy domains leave no empty attention panel", async ({ page }) => {
  await protectionAPI(page, observation());
  await page.route("**/api/v1/health", route => route.fulfill({ json: {
    status: "ok", managementRecovery: { state: "inactive", reason: "" }, evidence: { state: "ok" },
  } }));
  await page.goto("/zones/");
  await expect(page.getByRole("heading", { name: "Zones", exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Attention", exact: true })).not.toBeVisible();
});

test("an unavailable health endpoint cannot hide startup recovery uncertainty", async ({ page }) => {
  await protectionAPI(page, observation());
  await page.route("**/api/v1/health", route => route.fulfill({ status: 503, json: { error: "unavailable" } }));
  await page.goto("/zones/");
  const attention = page.getByRole("region", { name: "Attention", exact: true });
  await expect(attention.getByRole("status", { name: "Boot recovery" })).toContainText("Boot recovery state unknown");
  await expect(attention.getByText("Appliance health is unavailable.", { exact: true })).toBeVisible();
  await expect(attention.getByRole("status", { name: "Evidence health" })).toContainText("Evidence state unknown");
  await expect(attention.getByRole("status", { name: "Traffic protection" })).toHaveCount(0);
});
