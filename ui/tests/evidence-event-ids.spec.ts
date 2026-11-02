import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import type { TelemetryEvent } from "../lib/api";

const ids = ["9223372036854775809", "9223372036854775810"];
const events: TelemetryEvent[] = ids.map((id) => ({
  id, flowId: "same-flow", proto: "modbus", kind: "request", timestamp: "2026-10-31T10:00:00Z",
}));

test("adjacent high event IDs survive page merge, detail and JSON export", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    const json = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin", username: "containd", role: "admin" }
      : path.endsWith("/health") ? { evidence: { state: "ok" } }
        : path.endsWith("/events") ? {
          events: url.searchParams.has("cursor") ? events : [events[0]],
          nextCursor: url.searchParams.has("cursor") ? undefined : "older",
          historyTruncated: false,
        }
          : path.startsWith("/api/v1/events/") ? events.find((e) => path.endsWith(`/${e.id}`))
            : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/events");
  await page.goto("/events/");
  await loaded;
  await page.getByRole("button", { name: "Live", exact: true }).click();
  const older = page.waitForResponse((r) => new URL(r.url()).searchParams.get("cursor") === "older");
  await page.getByRole("button", { name: "Load older evidence", exact: true }).click();
  await older;
  for (const id of ids) {
    const inspection = page.locator(`[id="event-inspection-${id}"]`);
    const toggle = page.getByRole("button", { name: "Inspect event", exact: true });
    await toggle.nth(ids.indexOf(id)).focus();
    await page.keyboard.press("Enter");
    await expect(inspection).toBeVisible();
    const button = page.getByRole("button", { name: `Event ${id}`, exact: true });
    await expect(button).toHaveCount(1);
    const detail = page.waitForRequest((r) => new URL(r.url()).pathname === `/api/v1/events/${id}`);
    await button.click();
    await detail;
    const link = page.locator(`a[download='event-${id}.json']`);
    await expect(link).toBeVisible();
    const href = await link.getAttribute("href");
    expect(JSON.parse(decodeURIComponent(href!.split(",")[1])).id).toBe(id);
    const completed = page.waitForEvent("download");
    await link.click();
    const download = await completed;
    expect(JSON.parse(await readFile((await download.path())!, "utf8")).id).toBe(id);
  }
  expect(errors).toEqual([]);
});
