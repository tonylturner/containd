import { expect, test } from "@playwright/test";
import { openEditor } from "./fixtures/ics-editor";

for (const surface of ["ics", "firewall"]) {
  test(`${surface}: predicate editor exposes station and point selectors`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 1440, height: 1600 });
    await openEditor(page, surface, { protocol: "dnp3", functionCode: [0, 1], masters: [1], groups: [50], addresses: ["0-10"] });
    await expect(page.locator("div.fixed.inset-0")).toBeVisible();
    await page.getByText("Advanced selectors (saved values still apply)", { exact: true }).click();
    await expect(page.getByLabel("Masters (0-65519)")).toHaveValue("1");
    await expect(page.getByLabel("Point indexes", { exact: true })).toHaveValue("0-10");
    await page.screenshot({ path: testInfo.outputPath(`${surface}-editor.png`), fullPage: true, animations: "disabled" });
  });
}

for (const surface of ["ics", "firewall"]) {
  const save = surface === "ics" ? "Save filter" : "Save changes";
  const form = (page: import("@playwright/test").Page) => page.locator("div.fixed.inset-0");
  for (const [protocol, ics, changes, cleared] of [
    ["dnp3", { masters: [0, 65519], outstations: [2], groups: [50], variations: [0], addresses: ["0-4294967295"] }, [["Masters (0-65519)", ""], ["Variations (0-255)", ""]], ["masters", "variations"]],
    ["cip", { objectClasses: [4], instances: [0], attributes: [65535] }, [["Instances (0-65535)", ""], ["Attributes (0-65535)", ""]], ["instances", "attributes"]],
    ["cip", { tags: ["Program:Main.Motor.Speed"] }, [["Tag paths", ""]], ["tags"]],
    ["iec104", { typeIds: [46], cot: [6], originators: [0], negative: false, test: false, selectExecute: "execute" as const }, [["Cause of transmission (1-63)", ""], ["Originators (0-255)", ""]], ["cot", "originators"]],
  ] satisfies [string, import("../lib/api").ICSPredicate, [string, string][], string[]][]) {
    test(`${surface}: ${protocol} preserves all fields and clears ${cleared}`, async ({ page }) => {
      const seen = await openEditor(page, surface, { protocol, ...ics });
      await form(page).getByText("Advanced selectors (saved values still apply)", { exact: true }).click();
      for (const [label, value] of changes) await form(page).getByLabel(label, { exact: true }).fill(value);
      await form(page).getByRole("button", { name: "Preview impact" }).click();
      await expect.poll(() => seen.previews.length).toBe(1);
      const effective = { protocol, ...ics } as Record<string, unknown>;
      for (const key of cleared) delete effective[key];
      expect(seen.previews[0].ics).toMatchObject(effective);
      expect(JSON.stringify(seen.previews[0].ics)).not.toContain(":null");
      for (const key of cleared) expect(seen.previews[0].ics).not.toHaveProperty(key);
      await form(page).getByRole("button", { name: save }).click();
      await expect.poll(() => seen.patches.length).toBe(1);
      for (const key of cleared) expect(seen.patches[0].ics).toHaveProperty(key, null);
      expect(seen.saved().ics).toMatchObject(effective);
    });
  }
  for (const protocol of ["dnp3", "cip"]) {
    test(`${surface}: ${protocol} legacy unitId removal is explicit`, async ({ page }) => {
      const seen = await openEditor(page, surface, { protocol, unitId: 0 });
      await expect(form(page).getByRole("alert")).toContainText("Unit ID filtering is unavailable");
      await form(page).getByRole("button", { name: "Preview impact" }).click();
      await form(page).getByRole("button", { name: save }).click();
      expect(seen.previews).toHaveLength(0);
      expect(seen.patches).toHaveLength(0);
      await form(page).getByRole("button", { name: "Remove unit ID filter" }).click();
      await form(page).getByRole("button", { name: "Preview impact" }).click();
      await expect.poll(() => seen.previews.length).toBe(1);
      expect(seen.previews[0].ics).not.toHaveProperty("unitId");
      await form(page).getByRole("button", { name: save }).click();
      await expect.poll(() => seen.patches.length).toBe(1);
      expect(seen.patches[0].ics.unitId).toBeNull();
    });
  }
  test(`${surface}: invalid new field blocks save and preview`, async ({ page }) => {
    const seen = await openEditor(page, surface, { protocol: "dnp3", groups: [50] });
    await form(page).getByText("Advanced selectors (saved values still apply)", { exact: true }).click();
    await form(page).getByLabel("Masters (0-65519)").fill("65520");
    await form(page).getByRole("button", { name: "Preview impact" }).click();
    await form(page).getByRole("button", { name: save }).click();
    await expect(form(page).getByText(/must be an integer from 0 to 65519/)).toBeVisible();
    expect(seen.previews).toHaveLength(0);
    expect(seen.patches).toHaveLength(0);
  });
}
