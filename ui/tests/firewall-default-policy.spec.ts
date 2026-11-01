import { expect, test, type Page } from "@playwright/test";

const revision = "0123456789abcdef.1";
const differentRevision = `${revision.split(".")[0]}.${Number(revision.split(".")[1]) + 1}`;

async function openFirewall(page: Page, {
  count = 3, action = "DENY" as unknown, unavailable = false, mismatch = false, role = "admin",
  firewallMissing = false, omitAction = false,
} = {}) {
  const rules = Array.from({ length: count }, (_, i) => ({ id: `rule-${i}`, action: "ALLOW" }));
  await page.addInitScript((role) => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", role);
  }, role);
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown = {};
    if (path.endsWith("/auth/me") || path.endsWith("/auth/session")) json = { id: "user", role };
    if (path.endsWith("/config/diff")) json = { changed: false, changedSections: [] };
    if (path.endsWith("/firewall/rules")) json = rules;
    if (path.endsWith("/zones")) json = [{ name: "wan" }];
    if (path.endsWith("/routing")) json = { routes: [], rules: [], gateways: [] };
    if (path.endsWith("/firewall/nat")) json = { enabled: false };
    if (path.endsWith("/dataplane")) json = { captureInterfaces: [], dpiMock: false };
    if (path.endsWith("/config/candidate")) {
      if (unavailable) return route.fulfill({ status: 503, json: { error: "unavailable" } });
      json = firewallMissing ? {} : { firewall: { ...(omitAction ? {} : { defaultAction: action }), rules } };
      return route.fulfill({ json, headers: { "X-Containd-Revision": mismatch ? differentRevision : revision } });
    }
    await route.fulfill({ json, headers: { "X-Containd-Revision": revision } });
  });
  const loaded = page.waitForResponse("**/api/v1/config/candidate");
  await page.goto("/firewall/");
  await loaded;
}

for (const count of [0, 3]) {
  for (const [label, action, expected] of [
    ["DENY", "DENY", "DENY"],
    ["empty", "", "DENY"],
    ["omitted", undefined, "DENY"],
    ["ALLOW", "ALLOW", "ALLOW"],
    ["invalid", "RESET", "unknown"],
  ] as const) {
    test(`default ${label} is read-only and last with ${count} rules`, async ({ page }) => {
      await openFirewall(page, { count, action, omitAction: label === "omitted" });
      const region = page.getByRole("region", { name: "Firewall rules" });
      const fallback = region.getByRole("row", { name: "Default policy" });
      await expect(fallback.getByRole("status").first()).toHaveText(expected);
      await expect(region.locator("tbody tr").last()).toHaveAttribute("aria-label", "Default policy");
      await expect(region.locator("tbody tr[id]")).toHaveCount(count);
      await expect(fallback).toContainText("any → any");
      await expect(fallback.getByRole("cell", { name: "any", exact: true })).toHaveCount(1);
      await expect(fallback).toContainText("no enforcing rule allows, blocks or rejects traffic");
      await expect(fallback.getByRole("button")).toHaveCount(0);
      await expect(fallback.getByRole("link")).toHaveCount(0);
      await expect(fallback.getByText("Unmatched traffic allowed", { exact: true })).toHaveCount(expected === "ALLOW" ? 1 : 0);
    });
  }
}

for (const reason of ["unavailable", "mismatch", "firewallMissing"] as const) {
  test(`default is unknown, not deny, when ${reason}`, async ({ page }) => {
    await openFirewall(page, { [reason]: true });
    const fallback = page.getByRole("row", { name: "Default policy" });
    await expect(fallback.getByRole("status")).toHaveText("unknown");
    await expect(fallback).not.toContainText("DENY");
  });
}

test("view-only users see the default but no reorder or mutation controls", async ({ page }) => {
  await openFirewall(page, { role: "view", action: "ALLOW" });
  const region = page.getByRole("region", { name: "Firewall rules" });
  await expect(region.getByRole("row", { name: "Default policy" })).toContainText("ALLOW");
  await expect(region.locator("tbody tr[id]")).toHaveCount(3);
  const controls = region.getByRole("button");
  await expect(controls.filter({ hasNotText: /^Details for / })).toHaveCount(0);
  await expect(controls).toHaveCount(3);
  await region.getByRole("button", { name: "Details for rule-0", exact: true }).click();
  await expect(page.getByLabel("Details of rule-0", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Details of rule-0", { exact: true }).getByRole("button")).toHaveCount(0);
});

for (const count of [0, 3]) {
  test(`ALLOW default has one compact action badge and a readable warning at 1280px with ${count} rules`, async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await openFirewall(page, { action: "ALLOW", count });
    const fallback = page.getByRole("row", { name: "Default policy" });
    const action = fallback.getByRole("cell").filter({ has: page.getByRole("status").filter({ hasText: /^ALLOW$/ }) });
    await expect(action.getByRole("status")).toHaveCount(1);
    await expect(action).toHaveText("ALLOW");
    const warning = fallback.getByText("Unmatched traffic allowed", { exact: true });
    await expect(warning).toBeVisible();
    const description = fallback.getByRole("cell").filter({ hasText: "Applies when no enforcing rule" });
    await expect(description).toContainText("Unmatched traffic allowed");
    expect(await warning.evaluate((el) => el.getBoundingClientRect().height / parseFloat(getComputedStyle(el).lineHeight))).toBeLessThanOrEqual(2);
    expect(await action.getByRole("status").evaluate((el) => {
      const style = getComputedStyle(el);
      return (el.getBoundingClientRect().height - parseFloat(style.paddingTop) - parseFloat(style.paddingBottom)) / parseFloat(style.lineHeight);
    })).toBeLessThanOrEqual(1);
  });
}

test("a failed default refresh does not leave a previously reported action visible", async ({ page }) => {
  await openFirewall(page, { action: "ALLOW" });
  const fallback = page.getByRole("row", { name: "Default policy" });
  await expect(fallback.getByRole("status").first()).toHaveText("ALLOW");
  await page.route("**/api/v1/config/candidate", (route) => route.fulfill({
    status: 503, json: { error: "unavailable" },
  }));
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(fallback.getByRole("status")).toHaveText("unknown");
  await expect(fallback).not.toContainText("Unmatched traffic allowed");
});
