import { expect, test, type Page } from "@playwright/test";

async function openExport(page: Page, emptyCandidate = false) {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") {
      body = { id: "admin", username: "containd", role: "admin" };
    }
    if (path === "/api/v1/ids/rules") {
      body = { enabled: true, rules: emptyCandidate ? [] : [{ id: "rule-1", proto: "modbus" }] };
    }
    if (path === "/api/v1/ids/sources") body = [];
    if (path === "/api/v1/config/diff") body = { changed: false, changedSections: [] };
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  const loaded = page.waitForResponse("**/api/v1/ids/rules");
  await page.goto("/ids/");
  await loaded;
  await page.getByRole("button", { name: "Export", exact: true }).click();
}

for (const format of ["Snort", "Suricata"]) {
  for (const count of [0, 1, 3]) {
    test(`${format} download reports ${count} refused rules`, async ({ page }) => {
      await openExport(page);
      await page.route("**/api/v1/ids/export?**", (route) => route.fulfill({ contentType: "text/plain", body: count ? "# refused: test\n" : "alert tcp any any -> any any (sid:1;)\n", headers: { "X-Containd-Revision": "0123456789abcdef.1", "X-Containd-IDS-Refused": String(count) } }));
      const download = page.waitForEvent("download");
      await page.getByRole("button", { name: new RegExp(format) }).click();
      expect((await download).suggestedFilename()).toMatch(/\.rules$/);
      await expect(page.getByRole("status", { name: "Export result" })).toContainText(
        `Downloaded. ${count} rule${count !== 1 ? "s" : ""} refused.`,
      );
      if (count) await expect(page.getByRole("status", { name: "Export result" })).toContainText("refusal comments");
    });
  }
}

for (const [format, ext, prefix] of [["Sigma", ".yml", "#"], ["YARA", ".yar", "//"]]) {
  test(`${format} download reports refused native predicates`, async ({ page }) => {
    await openExport(page);
    await page.route("**/api/v1/ids/export?**", (route) => route.fulfill({ contentType: format === "Sigma" ? "text/yaml" : "text/plain", body: `${prefix} refused: {"rule_id":"rule-1","reason":"cannot preserve ${format === "Sigma" ? "srcAddr=10.0.0.0/8" : "proto=modbus"}"}\n`, headers: { "X-Containd-Revision": "0123456789abcdef.1", "X-Containd-IDS-Refused": "1" } }));
    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: new RegExp(format) }).click();
    expect((await download).suggestedFilename()).toMatch(new RegExp(`\\${ext}$`));
    await expect(page.getByRole("status", { name: "Export result" })).toContainText("1 rule refused.");
    await expect(page.getByRole("status", { name: "Export result" })).toContainText("refusal comments");
  });
}

test("failed export clears old counts and allows retry", async ({ page }) => {
  await openExport(page);
  let attempt = 0;
  await page.route("**/api/v1/ids/export?**", async (route) => {
    attempt++;
    if (attempt === 2) {
      await route.abort("failed");
    } else {
      await route.fulfill({ contentType: "text/plain", body: "", headers: { "X-Containd-Revision": "0123456789abcdef.1", "X-Containd-IDS-Refused": attempt === 1 ? "3" : "0" } });
    }
  });
  const button = page.getByRole("button", { name: /Snort/ });
  const initial = page.waitForEvent("download");
  await button.click();
  await initial;
  await expect(page.getByRole("status", { name: "Export result" })).toContainText("3 rules refused");
  await button.click();
  await expect(page.getByRole("status", { name: "Export result" })).toHaveCount(0);
  await expect(page.getByText("Failed to fetch", { exact: false })).toBeVisible();
  await expect(button).toBeEnabled();
  const download = page.waitForEvent("download");
  await button.click();
  await download;
  await expect(page.getByRole("status", { name: "Export result" })).toContainText("0 rules refused");
});

for (const header of [undefined, "", "-1", "1.5", "unknown"]) {
  test(`invalid refusal header (${header}) is not a false zero`, async ({ page }) => {
    await openExport(page);
    await page.route("**/api/v1/ids/export?**", (route) => route.fulfill({ contentType: "text/plain", body: "", headers: { "X-Containd-Revision": "0123456789abcdef.1", ...(header === undefined ? {} : { "X-Containd-IDS-Refused": header }) } }));
    await page.getByRole("button", { name: /Snort/ }).click();
    await expect(page.getByText("Export response is missing a valid refusal count.")).toBeVisible();
    await expect(page.getByRole("status", { name: "Export result" })).toHaveCount(0);
  });
}

test("empty candidate does not prevent exporting running rules", async ({ page }) => {
  await openExport(page, true);
  await expect(page.getByText("No candidate rules. Running rules can still be exported.")).toBeVisible();
  await expect(page.getByRole("button", { name: /Snort/ })).toBeEnabled();
});
