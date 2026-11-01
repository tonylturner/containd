import { expect, test } from "@playwright/test";
import type { IDSRule } from "../lib/api";

test("YARA import and rule rows distinguish enabled from evaluable", async ({ page }) => {
  const yara: IDSRule = {
    id: "yara-stored", title: "Stored YARA", sourceFormat: "yara", enabled: true,
    labels: { evaluable: "false" },
    conversionNotes: ["YARA rules are not evaluated against network DPI events"],
  };
  const partial: IDSRule = {
    id: "partial-snort", enabled: false, sourceFormat: "snort",
    labels: { evaluable: "false" }, conversionNotes: ["Unsupported source predicate"],
  };
  const rules: IDSRule[] = [partial, { id: "native", enabled: true }];
  let revision = "0123456789abcdef.1";
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async route => {
    const req = route.request();
    const path = new URL(req.url()).pathname.replace("/api/v1", "");
    if (path === "/ids/import") {
      expect(req.postDataBuffer()?.toString()).toContain("stored.yar");
      expect(req.headers()["x-containd-if-revision"]).toBe(revision);
      rules.push(yara);
      revision = "0123456789abcdef.2";
      return route.fulfill({ json: { imported: 1, skipped: 0, total: 3, format: "yara", rules: [yara] }, headers: { "X-Containd-Revision": revision, "X-Containd-Config": "staged" } });
    }
    const json = path.startsWith("/auth/") ? { id: "admin", role: "admin" }
      : path === "/ids/rules" ? { enabled: true, rules }
      : path === "/ids/sources" ? []
      : path === "/config/diff" ? { changed: false, changedSections: [] } : {};
    return route.fulfill({ json, headers: { "X-Containd-Revision": revision } });
  });
  const loaded = page.waitForResponse("**/api/v1/ids/rules");
  await page.goto("/ids/");
  await loaded;
  const partialRow = page.getByRole("row").filter({ hasText: "partial-snort" });
  await expect(partialRow).toContainText("Storage only — not evaluated");
  await expect(partialRow).toContainText(partial.conversionNotes![0]);
  await page.getByRole("button", { name: "Import", exact: true }).click();
  await expect(page.getByText("YARA is stored for inspection", { exact: false })).toBeVisible();
  await page.locator('input[type="file"]').setInputFiles({ name: "stored.yar", mimeType: "text/plain", buffer: Buffer.from('rule stored { condition: true }') });
  await page.getByRole("button", { name: "Import", exact: true }).last().click();
  const result = page.getByRole("region", { name: "Import result" });
  await expect(result).toContainText("1 imported, 0 skipped");
  await expect(result).toContainText("Storage only — not evaluated");
  await expect(result).toContainText(yara.conversionNotes![0]);
  await expect(result).not.toContainText(partial.conversionNotes![0]);
  const row = page.getByRole("row").filter({ hasText: "yara-stored" });
  await expect(row).toContainText("Storage only — not evaluated");
  await expect(row).toContainText(yara.conversionNotes![0]);
  await row.getByTitle("Click to disable").click();
  await expect(row).toContainText("Storage only — not evaluated");
  await row.getByTitle("Click to enable").click();
  await expect(row).toContainText("Storage only — not evaluated");
  await expect(page.getByText("2 / 3 rules enabled; 1 evaluable")).toBeVisible();
});
