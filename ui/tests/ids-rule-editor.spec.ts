import { expect, test, type Page } from "@playwright/test";
import type { IDSConfig, IDSRule } from "../lib/api";
import { CONFIG_STAGED } from "../lib/config-events";

const rule: IDSRule = { id: "site-modbus", title: "Modbus read", proto: "modbus", kind: "request", severity: "low",
  when: { field: "attr.function_code", op: "equals", value: 3 }, message: "Read observed", labels: { site: "plant" },
  contentMatches: [{ pattern: "read", nocase: true }], references: ["https://example.org/rule"], rawSource: "preserved source" };
async function setup(page: Page, compound = false, normalize = false) {
  const state = { revision: 1, cfg: { enabled: true, rules: [{ ...rule, ...(normalize ? { title: "  Modbus read  " } : {}), ...(compound ? { when: { all: [rule.when!] } } : {}) }] } as IDSConfig,
    writes: [] as { body: IDSConfig; base?: string }[], hold: null as Promise<void> | null };
  await page.route("**/api/v1/**", async route => {
    const req = route.request(), path = new URL(req.url()).pathname;
    if (path.endsWith("/ids/rules") && req.method() === "POST") {
      const body = req.postDataJSON(), base = req.headers()["x-containd-if-revision"];
      state.writes.push({ body, base });
      if (base !== `0123456789abcdef.${state.revision}`) return route.fulfill({ status: 412, json: { error: "Configuration changed", code: "config_revision_mismatch", currentRevision: `0123456789abcdef.${state.revision}` } });
      state.cfg = normalize ? { ...body, rules: body.rules?.map((r: IDSRule) => ({ ...r, title: r.title?.trim() })) } : body;
      state.revision++;
      if (state.hold) await state.hold;
    }
    const json = path.includes("/auth/") ? { id: "admin", role: "admin" }
      : path.endsWith("/ids/rules") ? state.cfg : path.endsWith("/ids/sources") ? []
        : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    return route.fulfill({ json, headers: { "X-Containd-Revision": `0123456789abcdef.${state.revision}` } });
  });
  await Promise.all([page.waitForResponse("**/ids/rules"), page.goto("/ids/")]);
  return state;
}

test("structured common fields preserve advanced fields and stage once with old-editor payload equality", async ({ page }) => {
  const state = await setup(page);
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Title", { exact: true }).fill("Site read");
  await dialog.getByRole("combobox", { name: "Severity", exact: true }).selectOption("high");
  await dialog.getByLabel("Match value", { exact: true }).fill("4");
  await dialog.getByRole("button", { name: "Save rule", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByText(/No additional Save is needed/)).toBeVisible();
  expect(state.writes).toEqual([{ base: "0123456789abcdef.1", body: { enabled: true, rules: [{ ...rule, title: "Site read", severity: "high", when: { ...rule.when, value: 4 } }] } }]);
});

test("Edit JSON remains the advanced path and preserves compound predicates", async ({ page }) => {
  const state = await setup(page, true);
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText(/compound or list condition/)).toBeVisible();
  await dialog.getByLabel("Title", { exact: true }).fill("Compound");
  await dialog.getByRole("button", { name: "Edit JSON", exact: true }).click();
  const expected = { ...state.cfg.rules![0], title: "Compound", labels: { site: "new" } };
  await dialog.getByRole("textbox", { name: "Rule JSON", exact: true }).fill(JSON.stringify(expected));
  await dialog.getByRole("button", { name: "Save rule", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(state.writes[0].body.rules).toEqual([expected]);
});

test("a revision conflict keeps the rule draft and offers a deliberate retry inside the dialog", async ({ page }) => {
  const state = await setup(page);
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Title", { exact: true }).fill("Kept draft");
  state.revision++;
  await dialog.getByRole("button", { name: "Save rule", exact: true }).click();
  await expect(dialog.getByRole("button", { name: "Keep my edits", exact: true })).toBeVisible();
  await dialog.getByRole("button", { name: "Keep my edits", exact: true }).click();
  expect(state.writes).toHaveLength(1);
  await expect(dialog.getByLabel("Title", { exact: true })).toHaveValue("Kept draft");
  await dialog.getByRole("button", { name: "Save rule", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(state.writes.map(w => w.base)).toEqual(["0123456789abcdef.1", "0123456789abcdef.2"]);
});

test("group description is staged with the group and retained on reload", async ({ page }) => {
  const state = await setup(page);
  await page.getByRole("button", { name: /^Groups/ }).click();
  await page.getByLabel("Name", { exact: true }).fill("Plant");
  await page.getByLabel("Filter", { exact: true }).fill("proto:modbus");
  await page.getByLabel("Description", { exact: true }).fill("Plant polling");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => state.writes.length).toBe(1);
  expect(state.writes[0].body.ruleGroups).toEqual([{ id: "plant", name: "Plant", filter: "proto:modbus", description: "Plant polling", enabled: true }]);
  await Promise.all([page.waitForResponse("**/ids/rules"), page.reload()]);
  await expect(page.getByText("Plant polling", { exact: true })).toBeVisible();
});

test("phone actions and keyboard dialog remain reachable without page overflow", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await setup(page);
  const edit = page.getByRole("button", { name: "Edit", exact: true });
  await edit.scrollIntoViewIfNeeded();
  const box = await edit.boundingBox();
  expect(box!.x + box!.width).toBeLessThanOrEqual(390);
  await edit.focus();
  await page.keyboard.press("Enter");
  await page.getByRole("dialog").getByLabel("Title", { exact: true }).fill("Mobile");
  await page.getByRole("dialog").getByRole("button", { name: "Save rule", exact: true }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});


test("a server-normalized rule is adopted, closes the dialog and shows success", async ({ page }) => {
  const state = await setup(page, false, true);
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Title", { exact: true }).fill("  Normalized title  ");
  await dialog.getByRole("button", { name: "Save rule", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(state.writes).toHaveLength(1);
  expect(state.writes[0].body.rules?.[0].title).toBe("  Normalized title  ");
  expect(state.cfg.rules?.[0].title).toBe("Normalized title");
  await expect(page.getByRole("cell", { name: "Normalized title", exact: true })).toBeVisible();
  await expect(page.getByText("IDS rules staged — commit to apply. No additional Save is needed.", { exact: true })).toBeVisible();
});

test("a normalized read overtaking the save receipt keeps success visible inside the retained dialog", async ({ page }) => {
  const state = await setup(page, false, true);
  let release!: () => void;
  state.hold = new Promise<void>(resolve => { release = resolve; });
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("button", { name: "Save rule", exact: true }).click();
  await expect.poll(() => state.writes.length).toBe(1);
  await Promise.all([
    page.waitForResponse(r => r.request().method() === "GET" && new URL(r.url()).pathname === "/api/v1/ids/rules"),
    page.evaluate(event => window.dispatchEvent(new CustomEvent(event)), CONFIG_STAGED),
  ]);
  const cell = page.getByRole("cell", { name: "Modbus read", exact: true });
  await expect(cell).toHaveAttribute("title", "Modbus read");
  release();
  await expect(dialog.getByRole("status")).toHaveText("IDS rules staged — commit to apply. No additional Save is needed.");
  expect(state.writes).toHaveLength(1);
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await expect(cell).toHaveAttribute("title", "Modbus read");
});
