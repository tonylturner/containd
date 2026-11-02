import { expect, test, type Page } from "@playwright/test";
import { observation, protectionAPI } from "./fixtures/protection-api";

async function ids(page: Page, holdFirstRead = false) {
  await protectionAPI(page, observation());
  const state = { groups: [{ id: "industrial", name: "Industrial", filter: "proto:modbus", enabled: true }] };
  let release = () => {};
  const ready = new Promise<void>(resolve => { release = resolve; });
  const writes: unknown[] = [];
  await page.route("**/api/v1/ids/rules", async route => {
    if (route.request().method() !== "GET") {
      writes.push(route.request().postDataJSON());
      return route.fulfill({ status: 500, json: { error: "unexpected write" } });
    }
    if (holdFirstRead) await ready;
    await route.fulfill({ json: { enabled: true, rules: [], ruleGroups: state.groups },
      headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  await page.route("**/api/v1/ids/sources", route => route.fulfill({ json: [] }));
  await page.goto("/ids/");
  await expect(page.getByRole("button", { name: "Groups", exact: true })).toBeVisible();
  return { state, release, writes };
}

test("saved values arriving after mount open Groups without overriding later user choices", async ({ page }) => {
  const { state, release, writes } = await ids(page, true);
  const groups = page.getByRole("button", { name: "Groups", exact: true });
  try {
    await expect(groups).toHaveAttribute("aria-expanded", "false");
    release();
    await expect(groups).toHaveAttribute("aria-expanded", "true");
    await expect(page.getByText("Industrial", { exact: true })).toBeVisible();
    await groups.focus();
    await page.keyboard.press("Space");
    await expect(groups).toBeFocused();
    await expect(groups).toHaveAttribute("aria-expanded", "false");
    await expect(page.getByText("1 group · non-default settings", { exact: true })).toBeVisible();
    const unchanged = page.waitForResponse("**/api/v1/ids/rules");
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await unchanged;
    await expect(page.getByText("1 group · non-default settings", { exact: true })).toBeVisible();
    await expect(groups).toHaveAttribute("aria-expanded", "false");
    state.groups = [];
    const loaded = page.waitForResponse("**/api/v1/ids/rules");
    await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:staged")));
    await loaded;
    await expect(page.getByText("0 groups", { exact: true })).toBeVisible();
    await expect(groups).toHaveAttribute("aria-expanded", "false");
    expect(writes).toEqual([]);
  } finally { release(); }
});

test("deleting the last IDS group keeps its editor and unfinished creation fields open", async ({ page }) => {
  const { writes } = await ids(page);
  const groups = page.getByRole("button", { name: "Groups", exact: true });
  await expect(groups).toHaveAttribute("aria-expanded", "true");
  await page.getByPlaceholder("e.g. ICS/Modbus").fill("Unfinished group");
  await page.getByRole("button", { name: "Del", exact: true }).click();
  await expect(groups).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByPlaceholder("e.g. ICS/Modbus")).toBeVisible();
  await expect(page.getByPlaceholder("e.g. ICS/Modbus")).toHaveValue("Unfinished group");
  await expect(page.getByText("No rule groups", { exact: true })).toBeVisible();
  expect(writes).toEqual([]);
});

test("configuration diagnostics remain operable when configuration mutations are disabled", async ({ page }) => {
  await protectionAPI(page, observation());
  await page.route("**/api/v1/config/backups", route => route.fulfill({ json: [] }));
  await page.route("**/api/v1/config/diff", route => route.fulfill({ status: 503, json: { error: "unavailable" } }));
  await page.goto("/config/");
  await expect(page.getByRole("alert").filter({ hasText: "Configuration unavailable" })).toBeVisible();
  const advanced = page.getByRole("button", { name: "Advanced", exact: true });
  await expect(advanced).toBeEnabled();
  await advanced.focus();
  await page.keyboard.press("Enter");
  await expect(advanced).toBeFocused();
  await expect(page.getByRole("heading", { name: "Explore config blocks", exact: true })).toBeVisible();
  const recovery = page.getByRole("button", { name: "Recovery", exact: true });
  await expect(recovery).toBeEnabled();
  await recovery.click();
  await expect(page.getByRole("button", { name: "Confirm", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Rollback", exact: true })).toBeDisabled();
});

for (const path of ["/firewall/", "/ics/"]) {
  test(`${path} shows the enforcement health cause exactly once without expanding`, async ({ page }) => {
    const reason = "schedule horizon could not be extended";
    await protectionAPI(page, observation(), { enforcement: "degraded", enforcementReason: reason });
    await page.goto(path);
    await expect(page.getByRole("status", { name: "Firewall enforcement degraded: degraded" })).toBeVisible();
    const cause = page.getByText(reason, { exact: true });
    await expect(cause).toHaveCount(1);
    await expect(cause).toBeVisible();
    await expect(cause.locator("xpath=ancestor::details")).toHaveCount(0);
  });
}

test("shared diagnostic details wrap long file paths at 390px", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 900 });
  await protectionAPI(page, observation());
  const path = `/data/${"generated".repeat(30)}.conf`;
  await page.route("**/api/v1/services/dns", route => route.fulfill({
    json: { enabled: true, upstreamServers: [] }, headers: { "X-Containd-Revision": "0123456789abcdef.1" },
  }));
  await page.route("**/api/v1/services/status", route => route.fulfill({ json: {
    faults: [], av: { available: false, error: "scanner offline" },
    dns: { enabled: true, running: true, pid: 42, config_path: path },
  } }));
  await page.goto("/system/services/dns/");
  const details = page.getByRole("button", { name: "Service details", exact: true });
  await details.focus();
  await page.keyboard.press("Enter");
  await expect(details).toHaveAttribute("aria-expanded", "true");
  const value = page.getByText(path, { exact: true });
  await expect(value).toBeVisible();
  expect(await value.evaluate(element => element.parentElement!.scrollWidth <= element.parentElement!.clientWidth)).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
});
