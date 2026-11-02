import { expect, test, type Page } from "@playwright/test";
import { observation, protectionAPI } from "./fixtures/protection-api";
import { entityChanges } from "../app/config/config-entity-changes";
import { fieldChanges } from "../app/config/config-field-changes";

const revision = "0123456789abcdef.1";
async function setup(page: Page) {
  await protectionAPI(page, observation());
  const state = { changed: true, changedSections: ["zones", "firewall"], running: { zones: null, firewall: { rules: null } }, candidate: { zones: [{ name: "ot" }], firewall: { rules: Array.from({ length: 6 }, (_, i) => ({ id: `rule-${i}`, action: "DENY" })) } } };
  await page.route("**/api/v1/config/diff", route => route.fulfill({ json: state, headers: { "X-Containd-Revision": revision } }));
  await page.route("**/api/v1/config/backups", route => route.fulfill({ json: [] }));
  return state;
}

test("null lists summarize added entities before advanced exact paths", async ({ page }) => {
  await setup(page);
  await page.goto("/config/?tab=diff");
  const firewall = page.getByRole("region", { name: "Firewall changes", exact: true });
  await expect(firewall).toContainText("6 firewall rules added");
  await expect(firewall).not.toContainText("Not set");
  await expect(firewall).not.toContainText("firewall.rules");
  await expect(page.getByRole("region", { name: "Zones changes", exact: true })).toContainText("Zone ot added");
  await page.getByRole("button", { name: "Advanced", exact: true }).click();
  await expect(page.getByRole("region", { name: "Firewall JSON changes", exact: true })).toContainText('"id": "rule-0"');
  const fields = page.getByRole("region", { name: "Firewall field changes", exact: true });
  await expect(fields).not.toContainText("null");
});

test("review actions remain visible after scrolling a long review at 390px", async ({ page }) => {
  await setup(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/config/?tab=diff");
  await expect(page.getByRole("region", { name: "Firewall changes", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Advanced", exact: true }).click();
  await page.getByRole("region", { name: "Firewall field changes", exact: true }).scrollIntoViewIfNeeded();
  for (const name of ["Commit", "Commit-confirmed"]) {
    const button = page.getByRole("button", { name, exact: true });
    const box = await button.boundingBox();
    expect(box).not.toBeNull();
    expect(box!.y).toBeGreaterThanOrEqual(0);
    expect(box!.y + box!.height).toBeLessThanOrEqual(844);
  }
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

for (const rejected of [false, true]) {
  test(`Validate keeps unsaved JSON and never stages (${rejected ? "refusal" : "valid"})`, async ({ page }) => {
    await setup(page);
    const writes: { path: string; body: unknown; revision?: string }[] = [];
    await page.route("**/api/v1/config/validate", async route => {
      writes.push({ path: "validate", body: route.request().postDataJSON(), revision: route.request().headers()["x-containd-if-revision"] });
      return route.fulfill({ status: rejected ? 400 : 200, json: rejected ? { error: "reserved management path cannot be disabled" } : { status: "valid" } });
    });
    await page.goto("/config/?tab=candidate");
    const editor = page.getByRole("textbox", { name: "Staged config JSON", exact: true });
    await expect(editor).toContainText('"zones"');
    const draft = '{"system":{"hostname":"unsaved"}}';
    await editor.fill(draft);
    await page.getByRole("button", { name: "Validate", exact: true }).click();
    await expect(page.getByText(rejected ? "Validation failed: reserved management path cannot be disabled" : "Configuration valid. Unsaved text has not been staged.", { exact: true })).toBeVisible();
    await expect(editor).toHaveValue(draft);
    expect(writes).toEqual([{ path: "validate", body: JSON.parse(draft), revision: undefined }]);
  });
}

for (const conflict of [false, true]) {
  test(`factory reset is typed, confirmed, revision guarded (${conflict ? "stale refusal" : "success"})`, async ({ page }) => {
    await setup(page);
    const writes: { body: unknown; revision?: string }[] = [];
    await page.route("**/api/v1/system/factory-reset", async route => {
      writes.push({ body: route.request().postDataJSON(), revision: route.request().headers()["x-containd-if-revision"] });
      return route.fulfill({ status: conflict ? 412 : 200, json: conflict ? { error: "changed", code: "config_revision_mismatch", currentRevision: "0123456789abcdef.2" } : { message: "Factory reset completed. Log in with the default credentials.", loggedOut: true }, headers: { "X-Containd-Revision": conflict ? "0123456789abcdef.2" : revision } });
    });
    await page.goto("/config/");
    await page.getByRole("button", { name: "Recovery", exact: true }).click();
    const reset = page.getByRole("button", { name: "Factory reset", exact: true });
    await expect(reset).toBeDisabled();
    await page.getByLabel("Factory reset confirmation", { exact: true }).fill("nuclear");
    await expect(reset).toBeDisabled();
    await page.getByLabel("Factory reset confirmation", { exact: true }).fill("NUCLEAR");
    await reset.click();
    expect(writes).toEqual([]);
    const dialog = page.getByRole("dialog");
    await expect(dialog).toContainText("immediately wipes configuration, users and audit history");
    await dialog.getByRole("button", { name: "Reset now", exact: true }).click();
    await expect.poll(() => writes.length).toBe(1);
    expect(writes).toEqual([{ body: { confirm: "NUCLEAR" }, revision }]);
    await expect(page.getByText(conflict ? "Configuration changed since you loaded it" : "Factory reset completed. Log in with the default credentials.", { exact: true })).toBeVisible();
  });
}

test("null keyed arrays never create a fictitious null to Not set field", () => {
  expect(fieldChanges(null, [{ id: "r1" }], "firewall.rules")).toEqual([{ kind: "item", label: "firewall rule r1", action: "Added" }]);
  expect(entityChanges(null, [{ id: "r1" }], "firewall.rules")).toEqual(["1 firewall rule added"]);
  expect(fieldChanges(null, ["tcp"], "protocols")).toEqual([{ kind: "value", label: "protocols.0", before: "Not set", after: '"tcp"' }]);
  expect(entityChanges({ token: "old" }, { token: "new" }, "service").join(" ")).not.toContain("new");
});
