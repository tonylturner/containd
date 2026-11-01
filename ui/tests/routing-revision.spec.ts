import { expect, test } from "@playwright/test";
import type { RoutingConfig } from "../lib/api";

const token = (n: number) => `0123456789abcdef.${n}`;

test("routing deletions acknowledge their base without clearing an unfinished gateway form", async ({ page }) => {
  let counter = 1;
  let routing: RoutingConfig = { gateways: [{ name: "one", address: "192.0.2.1" }, { name: "two", address: "192.0.2.2" }], routes: [], rules: [] };
  const writes: { revision?: string; body: RoutingConfig }[] = [];
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async route => {
    const req = route.request();
    const path = new URL(req.url()).pathname.replace("/api/v1", "");
    if (path === "/routing" && req.method() === "POST") {
      const body = req.postDataJSON();
      const revision = req.headers()["x-containd-if-revision"];
      writes.push({ revision, body });
      if (revision !== token(counter)) return route.fulfill({ status: 412, json: { error: "changed", code: "config_revision_mismatch", currentRevision: token(counter) } });
      routing = body;
      return route.fulfill({ json: routing, headers: { "X-Containd-Revision": token(++counter), "X-Containd-Config": "staged" } });
    }
    const json = path.startsWith("/auth/") ? { id: "admin", role: "admin" }
      : path === "/routing" ? routing
      : path === "/config/diff" ? { changed: false, changedSections: [], pendingConfirm: null, running: {}, candidate: {} } : {};
    return route.fulfill({ json, headers: { "X-Containd-Revision": token(counter) } });
  });
  await page.goto("/routing/");
  await page.getByText("Add gateway (advanced)", { exact: true }).click();
  await page.getByPlaceholder("isp1", { exact: true }).fill("unfinished");
  for (const [name, next] of [["one", 2], ["two", 3]] as const) {
    const row = page.getByRole("row").filter({ has: page.getByRole("cell", { name, exact: true }) });
    await row.getByRole("button", { name: "Delete", exact: true }).click();
    await expect.poll(() => counter).toBe(next);
    await expect(page.getByPlaceholder("isp1", { exact: true })).toHaveValue("unfinished");
  }
  expect(writes.map(write => write.revision)).toEqual([token(1), token(2)]);
});
