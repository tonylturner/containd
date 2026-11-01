import { expect, test, type Page } from "@playwright/test";

const token = (n: number) => `0123456789abcdef.${n}`;
const upload = { name: "rules.json", mimeType: "application/json", buffer: Buffer.from('[{"id":"kept-rule"}]') };
async function setup(page: Page) {
  const state = { counter: 1, writes: [] as { base?: string; body: unknown }[] };
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async route => {
    const req = route.request();
    const path = new URL(req.url()).pathname.replace("/api/v1", "");
    if (path === "/ids/restore") {
      const body = req.postDataJSON();
      const base = req.headers()["x-containd-if-revision"];
      state.writes.push({ base, body });
      if (base !== token(state.counter)) return route.fulfill({ status: 412, json: { error: "changed", code: "config_revision_mismatch", currentRevision: token(state.counter) } });
      return route.fulfill({ json: { count: 1 }, headers: { "X-Containd-Revision": token(++state.counter), "X-Containd-Config": "staged" } });
    }
    const json = path.startsWith("/auth/") ? { id: "admin", role: "admin" }
      : path === "/config/diff" ? { changed: false, changedSections: [], running: {}, candidate: {}, pendingConfirm: null }
      : path === "/config/backups" ? [] : {};
    return route.fulfill({ json, headers: { "X-Containd-Revision": token(state.counter) } });
  });
  await page.goto("/config/");
  await expect(page.getByText("0 committed detection rules. Restored rules are saved for review; commit applies them with the configuration.", { exact: true })).toBeVisible();
  return state;
}

test("IDS restore keeps the file and base on 412; Keep requires a deliberate second restore", async ({ page }) => {
  const state = await setup(page);
  state.counter++;
  await page.locator('input[type="file"]').last().setInputFiles(upload);
  await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toBeVisible();
  await expect(page.getByText("rules.json", { exact: true })).toBeVisible();
  expect(state.writes).toEqual([{ base: token(1), body: [{ id: "kept-rule" }] }]);
  await page.getByRole("button", { name: "Keep my edits", exact: true }).click();
  expect(state.writes).toHaveLength(1);
  await page.getByRole("button", { name: "Stage rule restore", exact: true }).click();
  await expect.poll(() => state.writes.length).toBe(2);
  expect(state.writes[1]).toEqual({ base: token(2), body: state.writes[0].body });
  await expect(page.getByText("IDS restore staged (1 rules) — commit to apply.", { exact: true })).toBeVisible();
  await expect(page.getByText("rules.json", { exact: true })).toHaveCount(0);
});

test("IDS restore Reload discards the file and reads a new base without retrying", async ({ page }) => {
  const state = await setup(page);
  state.counter++;
  await page.locator('input[type="file"]').last().setInputFiles(upload);
  await expect(page.getByRole("button", { name: "Reload", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Reload", exact: true }).click();
  await expect(page.getByText("rules.json", { exact: true })).toHaveCount(0);
  expect(state.writes).toHaveLength(1);
  await page.locator('input[type="file"]').last().setInputFiles(upload);
  await expect.poll(() => state.writes.length).toBe(2);
  expect(state.writes[1].base).toBe(token(2));
});
