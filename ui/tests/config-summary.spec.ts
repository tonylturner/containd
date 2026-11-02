import { expect, test, type Page } from "@playwright/test";
import { fieldChanges } from "../app/config/config-field-changes";
import { observation, protectionAPI } from "./fixtures/protection-api";

const rules = [
  { id: "r6-rule-1", description: "First", action: "ALLOW", log: true },
  { id: "r6-rule-2", description: "Second", action: "ALLOW" },
  { id: "r6-rule-3", description: "Third", action: "DENY" },
];

async function review(page: Page, running: Record<string, unknown>, candidate: Record<string, unknown>) {
  await protectionAPI(page, observation());
  await page.route("**/api/v1/config/diff", route => route.fulfill({
    json: { changed: true, changedSections: Object.keys(candidate), running, candidate },
    headers: { "X-Containd-Revision": "0123456789abcdef.1" },
  }));
  await page.route("**/api/v1/config/backups", route => route.fulfill({ json: [] }));
  await page.goto("/config/?tab=diff");
}

test("pure firewall reorder shows one order line and no invented field changes", async ({ page }) => {
  await review(page, { firewall: { rules } }, { firewall: { rules: [rules[1], rules[2], rules[0]] } });
  const summary = page.getByRole("region", { name: "Firewall changes", exact: true });
  await expect(summary.locator("dd")).toHaveText(["Order changed: r6-rule-2, r6-rule-3, r6-rule-1"]);
  await expect(summary.locator('[aria-label="Old value"], [aria-label="New value"]')).toHaveCount(0);
  const advanced = page.getByRole("button", { name: "Advanced", exact: true });
  await expect(advanced).toHaveAttribute("aria-expanded", "false");
  await advanced.click();
  const raw = page.getByRole("region", { name: "Firewall JSON changes", exact: true });
  await expect(raw).toBeVisible();
  await expect(raw.getByText('"id": "r6-rule-1",', { exact: true })).toHaveCount(2);
  await expect(raw).toContainText('"log": true');
  for (const width of [1280, 390]) {
    await page.setViewportSize({ width, height: 844 });
    await expect(summary).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  }
});

test("reorder plus one field edit stays attached to the firewall rule identity", async ({ page }) => {
  const edited = { id: rules[0].id, description: rules[0].description, action: rules[0].action };
  await review(page, { firewall: { rules } }, { firewall: { rules: [rules[1], rules[2], edited] } });
  const summary = page.getByRole("region", { name: "Firewall changes", exact: true });
  await expect(summary.locator("dt")).toHaveText(["firewall.rules", "firewall rule r6-rule-1: log"]);
  await expect(summary.locator("dd").first()).toHaveText("Order changed: r6-rule-2, r6-rule-3, r6-rule-1");
  await expect(summary.locator('[aria-label="Old value"]')).toHaveText("true");
  await expect(summary.locator('[aria-label="New value"]')).toHaveText("Not set");
});

test("added and removed entries are explicit and secret values remain hidden", async ({ page }) => {
  await review(page,
    { firewall: { rules: [rules[0]] }, services: { vpn: { wireguard: { privateKey: "old redacted placeholder" } } } },
    { firewall: { rules: [rules[1]] }, services: { vpn: { wireguard: { privateKey: "new redacted placeholder" } } } },
  );
  const firewall = page.getByRole("region", { name: "Firewall changes", exact: true });
  await expect(firewall.locator("dt")).toContainText(["firewall.rules", "firewall rule r6-rule-2"]);
  await expect(firewall.getByText("Added", { exact: true })).toBeVisible();
  await expect(firewall.getByText("Removed", { exact: true })).toBeVisible();
  await expect(firewall.getByText("firewall rule r6-rule-1: log", { exact: true })).toBeVisible();
  const services = page.getByRole("region", { name: "Services changes", exact: true });
  await expect(services.getByText("Secret value changed (hidden).", { exact: true })).toBeVisible();
  await expect(services).not.toContainText("redacted placeholder");
  await expect(services.locator('[aria-label="Old value"], [aria-label="New value"]')).toHaveCount(0);
});

for (const [section, label] of [["zones", "Zones"], ["interfaces", "Interfaces"]] as const) {
  test(`${section} match by name rather than array index`, async ({ page }) => {
    const items = [{ name: "lan", description: "Internal" }, { name: "wan", description: "External" }];
    await review(page, { [section]: items }, { [section]: [items[1], items[0]] });
    const summary = page.getByRole("region", { name: `${label} changes`, exact: true });
    await expect(summary.locator("dd")).toHaveText(["Order changed: wan, lan"]);
    await expect(summary.locator('[aria-label="Old value"]')).toHaveCount(0);
  });
}

test("keyed additions and removals retain their non-key fields", () => {
  expect(fieldChanges([{ id: "old", action: "ALLOW" }], [{ id: "new", action: "DENY" }], "firewall.rules")).toEqual([
    { kind: "order", label: "firewall.rules", items: ["new"] },
    { kind: "item", label: "firewall rule new", action: "Added" },
    { kind: "value", label: "firewall rule new: action", before: "Not set", after: '"DENY"' },
    { kind: "item", label: "firewall rule old", action: "Removed" },
    { kind: "value", label: "firewall rule old: action", before: '"ALLOW"', after: "Not set" },
  ]);
  expect(fieldChanges(undefined, [{ id: "new" }], "firewall.rules")).toEqual([
    { kind: "item", label: "firewall rule new", action: "Added" },
  ]);
  expect(fieldChanges([{ id: "old" }], [], "firewall.rules")).toEqual([
    { kind: "item", label: "firewall rule old", action: "Removed" },
  ]);
});

test("keyed secret changes stay hidden and identifier text is not a field name", () => {
  expect(fieldChanges(
    [{ id: "token-rule", log: false, credentials: { password: "old placeholder" } }],
    [{ id: "token-rule", log: true, credentials: { password: "new placeholder" } }],
    "firewall.rules",
  )).toEqual([
    { kind: "value", label: "firewall rule token-rule: log", before: "false", after: "true" },
    { kind: "secret", label: "firewall rule token-rule: credentials" },
  ]);
});

test("unkeyed arrays, duplicate keys and container changes do not hide changes", () => {
  expect(fieldChanges(["tcp"], ["udp"], "protocols")).toEqual([
    { kind: "value", label: "protocols.0", before: '"tcp"', after: '"udp"' },
  ]);
  expect(fieldChanges([{ id: "same", log: false }, { id: "same" }], [{ id: "same", log: true }, { id: "same" }], "rules")).toEqual([
    { kind: "value", label: "rules.0.log", before: "false", after: "true" },
  ]);
  expect(fieldChanges([], {}, "settings")).toEqual([
    { kind: "value", label: "settings", before: "[]", after: "{}" },
  ]);
});
