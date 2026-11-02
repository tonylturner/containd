import { expect, test } from "@playwright/test";
import { observation, protectionAPI } from "./fixtures/protection-api";

for (const conflict of [false, true]) {
  test(`template preview remains exempt and staging is revision guarded (${conflict ? "stale" : "success"})`, async ({ page }) => {
    await protectionAPI(page, observation());
    const revision = "0123456789abcdef.1";
    const headers = { "X-Containd-Revision": revision };
    await page.route("**/api/v1/templates/ics", route => route.fulfill({ json: [{ name: "Read-only", description: "Read functions", protocol: "modbus" }] }));
    await page.route("**/api/v1/zones", route => route.fulfill({ json: [{ name: "ot" }], headers }));
    await page.route("**/api/v1/dataplane", route => route.fulfill({ json: { dpiMode: "monitor" }, headers }));
    const writes: { body: any; revision?: string }[] = [];
    await page.route("**/api/v1/templates/ics/apply", async route => {
      const body = route.request().postDataJSON();
      writes.push({ body, revision: route.request().headers()["x-containd-if-revision"] });
      return route.fulfill({ status: conflict && !body.preview ? 412 : 200, json: conflict && !body.preview ? { error: "changed", code: "config_revision_mismatch", currentRevision: "0123456789abcdef.2" } : { rules: [], created: 0 }, headers });
    });
    await page.goto("/templates/");
    await page.getByRole("button", { name: "Generate Rules", exact: true }).click();
    await page.getByRole("button", { name: "Preview", exact: true }).click();
    await expect(page.getByText("No rules generated with the current parameters.", { exact: true })).toBeVisible();
    expect(writes).toEqual([{ body: { template: "Read-only", mode: "", preview: true }, revision: undefined }]);
    await page.getByRole("button", { name: "Stage", exact: true }).click();
    await expect.poll(() => writes.length).toBe(2);
    expect(writes[1]).toEqual({ body: { template: "Read-only", mode: "" }, revision });
    await expect(page.getByText(conflict ? "Configuration changed since you loaded it" : 'Template "Read-only" staged — commit to apply. 0 rules.', { exact: true })).toBeVisible();
  });
}
