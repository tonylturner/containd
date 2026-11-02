import { expect, test } from "@playwright/test";
import { observation, protectionAPI } from "./fixtures/protection-api";

for (const width of [1280, 390]) {
  for (const [path, help] of [
    ["/system/services/", "Embedded resolver with upstream forwarding and caching."],
    ["/firewall/", "Monitor rules observe independently and never admit or block. Other enforcing rules and scopes still apply. Monitoring does not start learning."],
  ] as const) {
    test(`${path} info marker stays square, labelled and keyboard reachable at ${width}px`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: 844 });
      await protectionAPI(page, observation());
      await page.goto(path);
      if (path === "/firewall/") {
        const settings = page.getByRole("button", { name: /^DPI settings/ });
        await expect(settings).toHaveAttribute("aria-expanded", "false");
        await settings.focus();
        await page.keyboard.press("Enter");
      }
      const tip = page.getByRole("img", { name: `Info: ${help}`, exact: true });
      await expect(tip).toBeVisible();
      await page.evaluate(() => document.fonts.ready);
      await expect(tip).toHaveCSS("width", "16px");
      await expect(tip).toHaveCSS("height", "16px");
      await expect(tip).toHaveCSS("line-height", "10px");
      await expect(tip).toHaveAttribute("tabindex", "0");
      await tip.focus();
      await expect(tip).toBeFocused();
      await expect(tip).toHaveCSS("box-shadow", /rgb\(245, 158, 11\) 0px 0px 0px 4px/);
      const tooltip = tip.locator("..").getByRole("tooltip");
      await expect(tooltip).toHaveText(help);
      await expect(tooltip).toHaveCSS("opacity", "1");
      const box = (await tooltip.boundingBox())!;
      expect(box.x).toBeGreaterThanOrEqual(8);
      expect(box.x + box.width).toBeLessThanOrEqual(width - 8);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
      await page.screenshot({ path: testInfo.outputPath("info-tip.png") });
      await page.keyboard.press("Tab");
      await expect(tip).not.toBeFocused();
    });
  }
}
