import { expect, test, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { dataset, mockLearner } from "./fixtures/learner";
import { withheldReason, withheldReasons } from "../app/pcap/withheld-reasons";

async function openDataset(page: Page) {
  const loaded = page.waitForResponse(r => new URL(r.url()).pathname === "/api/v1/learn/datasets");
  await page.goto("/pcap/");
  await loaded;
  await page.getByRole("button", { name: "Open capture-1", exact: true }).click();
  await expect(page.getByRole("table", { name: "Suggestion review", exact: true })).toBeVisible();
}

test("every learner withholding code has an explanation and remedy", () => {
  const source = ["../pkg/evidence/store.go", "../pkg/dp/learn/binding.go"]
    .map(path => readFileSync(path, "utf8")).join("\n");
  const codes = [...source.matchAll(/WithheldReason\s*=\s*"([^"]+)"/g)].map(match => match[1]);
  expect(Object.keys(withheldReasons).sort()).toEqual(codes.sort());
  for (const code of codes) expect(withheldReason(code)).toMatch(/\.\s.+\./);
  expect(withheldReason("future_code")).toBe("Unrecognized reason (future_code)");
  expect(withheldReason("toString")).toBe("Unrecognized reason (toString)");
});

for (const width of [1280, 390]) {
  test(`suggestions have compact scope and keyboard-expandable evidence at ${width}px`, async ({ page }) => {
    const state = await mockLearner(page);
    state.suggestions[1].content.requiresCoordinateReview = true;
    await page.setViewportSize({ width, height: 900 });
    await openDataset(page);
    const table = page.getByRole("table", { name: "Suggestion review", exact: true });
    const row = table.getByRole("row").filter({ has: page.getByLabel("Select iec-1", { exact: true }) });
    await expect(row).toContainText("192.0.2.10 → 192.0.2.20");
    await expect(row).toContainText("tcp/2404");
    await expect(page.getByLabel("Select iec-1", { exact: true })).toBeDisabled();
    const inspect = row.getByRole("button", { name: "Inspect suggestion" });
    await expect(inspect).toHaveAttribute("aria-expanded", "false");
    await inspect.focus();
    await page.keyboard.press("Enter");
    const article = page.getByRole("article", { name: "Suggestion iec-1", exact: true });
    await expect(article).toContainText("monitor, never enforce");
    const approve = article.getByRole("button", { name: "Review and approve", exact: true });
    await expect(approve).toBeDisabled();
    await article.getByRole("checkbox").check();
    await approve.click();
    await page.getByRole("dialog").getByRole("button", { name: "Review", exact: true }).click();
    await expect(page.getByLabel("Select iec-1", { exact: true })).toBeEnabled();
    await expect(page.getByLabel("Select iec-1", { exact: true })).not.toBeChecked();
    await page.getByLabel("Select iec-1", { exact: true }).check();
    await page.getByRole("button", { name: "Stage 1 selected", exact: true }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toContainText(/monitor/i);
    await dialog.getByRole("button", { name: "Stage", exact: true }).click();
    await expect.poll(() => state.writes.filter(w => w.path === "/learn/apply").length).toBe(1);
    expect(state.writes.find(w => w.path === "/learn/apply")!.body.selections).toEqual([{ id: "iec-1", revision: 3 }]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  });
}

test("withheld labels and remedies are visible without opening technical details", async ({ page }) => {
  await mockLearner(page);
  await page.route("**/api/v1/learn/generate", route => {
    route.request().postDataJSON();
    return route.fulfill({ json: { suggestions: [], withheld: {
      incomplete_parent: 2, modbus_fc23_roles: 1, modbus_write_values_or_masks: 3,
      missing_selector: 1, unsupported_operation: 1, future_code: 4,
    } } });
  });
  await openDataset(page);
  await page.getByRole("button", { name: "Generate suggestions", exact: true }).click();
  for (const code of ["incomplete_parent", "modbus_fc23_roles", "modbus_write_values_or_masks", "missing_selector", "unsupported_operation", "future_code"]) {
    await expect(page.getByText(`${withheldReason(code)}:`, { exact: false })).toBeVisible();
  }
});

test("collapsed evidence does not hide certification failures or withholding causes", async ({ page }) => {
  const state = await mockLearner(page);
  state.suggestions[0].proof!.positive.failed = 1;
  state.suggestions[0].content.withheld = ["unsupported_operation"];
  await openDataset(page);
  const table = page.getByRole("table", { name: "Suggestion review", exact: true });
  const row = table.getByRole("row").filter({ has: page.getByLabel("Select modbus-1", { exact: true }) });
  await expect(row).toContainText("1 replay failure(s)");
  await expect(row.getByText(withheldReason("unsupported_operation"), { exact: true })).toBeVisible();
  await expect(row.getByRole("button", { name: "Inspect suggestion" })).toHaveAttribute("aria-expanded", "false");
  await expect(page.getByLabel("Select modbus-1", { exact: true })).toBeDisabled();
});

for (const fail of [false, true]) {
  test(`dataset deletion is confirmed and ${fail ? "preserves evidence on failure" : "refreshes immediately without deleting staged rules or PCAPs"}`, async ({ page }) => {
    const state = await mockLearner(page);
    const deletes: string[] = [];
    await page.route("**/api/v1/learn/datasets/capture-1", async route => {
      expect(route.request().method()).toBe("DELETE");
      expect(route.request().headers()["x-containd-if-revision"]).toBeUndefined();
      deletes.push(route.request().url());
      if (!fail) state.datasets = [];
      await route.fulfill({ status: fail ? 503 : 200, json: fail ? { error: "evidence store unavailable" } : {} });
    });
    await openDataset(page);
    const remove = page.getByRole("button", { name: `Delete dataset ${dataset.id}`, exact: true });
    await remove.click();
    await expect(page.getByRole("dialog")).toContainText("Immediately delete");
    await expect(page.getByRole("dialog")).toContainText("Already staged rules and the original PCAP file are not deleted");
    expect(deletes).toEqual([]);
    await page.getByRole("dialog").getByRole("button", { name: "Cancel", exact: true }).click();
    expect(deletes).toEqual([]);
    await remove.click();
    await page.getByRole("dialog").getByRole("button", { name: "Delete dataset", exact: true }).click();
    await expect.poll(() => deletes.length).toBe(1);
    if (fail) {
      await expect(page.getByText("evidence store unavailable", { exact: true })).toBeVisible();
      await expect(remove).toBeEnabled();
    } else {
      await expect(page.getByText(/Dataset capture-1 deleted immediately/)).toBeVisible();
      await expect(page.getByLabel("Dataset review", { exact: true })).toHaveCount(0);
      await expect(page.getByText("No retained datasets.", { exact: false })).toBeVisible();
    }
    expect(state.writes).toEqual([]);
  });
}

test("viewer cannot delete datasets", async ({ page }) => {
  const state = await mockLearner(page, "viewer");
  await openDataset(page);
  await expect(page.getByRole("button", { name: /Delete dataset/ })).toHaveCount(0);
  expect(state.writes).toEqual([]);
});

test("collecting dataset deletion is disabled until collection seals", async ({ page }) => {
  const state = await mockLearner(page);
  state.datasets[0].state = "collecting";
  await page.goto("/pcap/");
  await expect(page.getByRole("button", { name: "Delete dataset capture-1", exact: true })).toBeDisabled();
  expect(state.writes).toEqual([]);
});
