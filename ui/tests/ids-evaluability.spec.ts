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

test("large imports summarize all rules but bound attention rows and can be dismissed", async ({ page }) => {
  const imported: IDSRule[] = Array.from({ length: 2000 }, (_, i) => ({
    id: `imported-${i}`, sourceFormat: "suricata", enabled: i % 2 === 0,
    // 500 storage-only; 1,000 with notes, including 250 storage-only.
    labels: { evaluable: i % 4 === 0 ? "false" : "true" },
    conversionNotes: i % 8 < 4 ? ["Review converted predicate"] : [],
  }));
  let rules: IDSRule[] = [];
  let revision = "0123456789abcdef.1";
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async route => {
    const req = route.request();
    const path = new URL(req.url()).pathname.replace("/api/v1", "");
    if (path === "/ids/import") {
      expect(req.postDataBuffer()?.toString()).toContain("large.rules");
      expect(req.headers()["x-containd-if-revision"]).toBe(revision);
      rules = imported;
      revision = "0123456789abcdef.2";
      return route.fulfill({
        json: { imported: imported.length, skipped: 3, total: rules.length, format: "suricata", rules: imported },
        headers: { "X-Containd-Revision": revision, "X-Containd-Config": "staged" },
      });
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
  await page.getByRole("button", { name: "Import", exact: true }).click();
  await page.locator('input[type="file"]').setInputFiles({
    name: "large.rules", mimeType: "text/plain", buffer: Buffer.from('alert tcp any any -> any 443 (sid:1;)'),
  });
  await page.getByRole("button", { name: "Import", exact: true }).last().click();
  const result = page.getByRole("region", { name: "Import result" });
  await expect(result).toContainText("2,000 imported, 3 skipped");
  await expect(result).toContainText("1,500 evaluable, 500 storage-only, 1,000 with conversion notes");
  const attention = result.getByRole("list", { name: "Rules needing attention" });
  await expect(attention.getByRole("listitem")).toHaveCount(20);
  const expectedAttention = imported.filter(r => r.labels?.evaluable === "false" || r.conversionNotes!.length > 0);
  await expect(attention.locator("li > span")).toHaveText(expectedAttention.slice(0, 20).map(r => r.id));
  await expect(result).toContainText("1,230 more need attention — see the Rules table");
  // Clean evaluable rules may appear in the table, but never in the result list.
  await expect(result.getByText("imported-5", { exact: true })).toHaveCount(0);
  await expect(result.getByText(expectedAttention[20].id, { exact: true })).toHaveCount(0);
  await result.getByRole("button", { name: "Dismiss", exact: true }).click();
  await expect(result).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Rules 2,000", exact: true })).toBeFocused();
  await expect(page.getByRole("row").filter({ hasText: "imported-0" })).toContainText("Storage only — not evaluated");
});
