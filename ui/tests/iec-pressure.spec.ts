import { expect, test } from "@playwright/test";

import { pressure } from "./fixtures/iec104-pressure";

for (const unavailable of [false, true]) {
  test(
    unavailable
      ? "IEC pressure unavailable never shows zero pressure"
      : "IEC pressure shows live gauges, reasons and fixed limits",
    async ({ page }) => {
      const errors: string[] = [];
      page.on("pageerror", (err) => errors.push(String(err)));
      await page.route("**/api/v1/**", async (route) => {
        const path = new URL(route.request().url()).pathname;
        let body: unknown = {};
        let status = 200;
        if (path.endsWith("/diagnostics/iec104")) {
          body = unavailable ? { error: "engine unavailable" } : pressure;
          status = unavailable ? 503 : 200;
        } else if (path.endsWith("/auth/me") || path.endsWith("/auth/session"))
          body = { id: "admin", username: "containd", role: "admin" };
        else if (
          path.endsWith("/interfaces") ||
          path.endsWith("/interfaces/state")
        )
          body = [];
        else if (path.endsWith("/health"))
          body = {
            status: "ok",
            iec104Enforcement: { active: false, healthy: true },
          };
        await route.fulfill({
          status,
          contentType: "application/json",
          body: JSON.stringify(body),
        });
      });
      await page.goto("/diagnostics");
      await expect(
        page.getByText("IEC 104 holdback pressure", { exact: true }),
      ).toBeVisible();
      if (unavailable) {
        await expect(
          page
            .getByRole("status")
            .filter({ hasText: "IEC 104 diagnostics unavailable" }),
        ).toBeVisible();
        await expect(
          page.getByRole("table", { name: "IEC 104 current pressure" }),
        ).toHaveCount(0);
      } else {
        const table = page.getByRole("table", {
          name: "IEC 104 current pressure",
        });
        await expect(
          table.getByRole("row").filter({ hasText: "Held packets" }),
        ).toContainText("12");
        await expect(table).toContainText("256 global / 32 per session");
        await expect(table).toContainText("0.625 s");
        await expect(table).toContainText("4096 tuple slots");
        await expect(
          page.getByText("Denied command", { exact: true }),
        ).toBeVisible();
        await expect(
          page.getByText("Bound / saturation", { exact: true }),
        ).toBeVisible();
        if (process.env.IEC104_PRESSURE_SCREENSHOT)
          await page.screenshot({
            path: process.env.IEC104_PRESSURE_SCREENSHOT,
            fullPage: true,
          });
      }
      expect(errors).toEqual([]);
    },
  );
}
