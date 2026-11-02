import { expect, test, type Page } from "@playwright/test";
import { CONFIG_COMMITTED } from "../lib/config-events";

const counterSince = "2026-11-01T23:51:44.696958333Z";

const rule = {
  id: "plc-read", description: "Read holding registers", action: "ALLOW", log: true,
  sourceZones: ["it", "engineering"], destZones: ["ot", "safety"],
  protocols: [{ name: "tcp", port: "502" }, { name: "udp", port: "20000" }],
  sources: ["10.0.0.5/32"], destinations: ["10.1.0.7/32"], identities: ["operator"],
  viaForwards: ["plc-forward"],
  schedule: { daysOfWeek: ["Monday"], startTime: "08:00", endTime: "17:00", timezone: "UTC" },
  ics: { protocol: "modbus", mode: "monitor", functionCode: [3], addresses: ["10-20"] },
};

async function open(page: Page, dataplane: object = {}, coverageFails = false, settingsFail = false) {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async route => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/dataplane" && settingsFail) {
      return route.fulfill({ status: 502, json: { error: "settings unavailable" } });
    }
    if (path === "/api/v1/dataplane/ics-coverage" && coverageFails) {
      return route.fulfill({ status: 502, json: { error: "coverage read failed" } });
    }
    const coverage = { ruleId: rule.id, protocol: "modbus", mode: "monitor", state: "monitoring", reasons: [] };
    const responses: Record<string, unknown> = {
      "/auth/me": { id: "admin", role: "admin" }, "/auth/session": { id: "admin", role: "admin" },
      "/config/diff": { changed: false, changedSections: [] },
      "/config/candidate": { firewall: { rules: [rule], defaultAction: "DENY" } },
      "/firewall/rules": [rule], "/zones": [], "/routing": { gateways: [], routes: [], rules: [] },
      "/dataplane": { captureInterfaces: [], dpiMock: false, ...dataplane },
      "/dataplane/ics-coverage": { candidate: [coverage], applied: [coverage] },
      "/firewall/counters": { since: counterSince, snapshotVersion: "a", rules: [
        { ruleId: rule.id, action: "ALLOW", packets: 7, bytes: 420 },
      ] },
      "/firewall/shadow-counters": { available: true, since: counterSince, snapshotVersion: "a", unit: "messages", rules: [
        { ruleId: rule.id, shadowMatches: 12, wouldAllow: 9, wouldDeny: 3 },
      ] },
    };
    await route.fulfill({ json: responses[path.replace("/api/v1", "")] ?? {}, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  const loaded = page.waitForResponse(r => new URL(r.url()).pathname === "/api/v1/firewall/rules");
  await page.goto("/firewall/");
  await loaded;
}

async function failRefresh(page: Page, background = false) {
  await page.route("**/api/v1/dataplane", route => route.fulfill({
    status: 502, json: { error: "settings unavailable" },
  }));
  if (background) {
    await page.evaluate(name => window.dispatchEvent(new CustomEvent(name)), CONFIG_COMMITTED);
  } else {
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
  }
  await expect(page.getByRole("alert").filter({ hasText: "Configuration unavailable." })).toBeVisible();
}

test("seven-column rules expand by keyboard and retain every moved field", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await open(page);
  const table = page.getByRole("region", { name: "Firewall rules" });
  expect(await table.getByRole("table").evaluate(el => getComputedStyle(el).display)).toBe("table");
  expect(await table.locator("tbody tr[id]").evaluate(el => getComputedStyle(el).display)).toBe("table-row");
  await expect(table.getByRole("columnheader")).toHaveText(["Order", "Description", "Zones", "Protocols", "Action", "Hits", "Actions"]);
  const button = page.getByRole("button", { name: `Inspect rule ${rule.id}`, exact: true });
  await expect(button).toHaveText("Inspect rule");
  await expect(button).toHaveAttribute("aria-expanded", "false");
  await expect(page.getByLabel(`Details of ${rule.id}`, { exact: true })).toHaveCount(0);
  await button.focus();
  await page.keyboard.press("Enter");
  await expect(button).toBeFocused();
  await expect(button).toHaveAttribute("aria-expanded", "true");
  const detail = page.getByLabel(`Details of ${rule.id}`, { exact: true });
  for (const label of ["Conditions", "ICS Filter", "Hits", "Shadow matches", "Log", "Exact matching values"]) {
    await expect(detail.locator("dt").getByText(label, { exact: true })).toBeVisible();
  }
  for (const value of ["10.0.0.5/32", "10.1.0.7/32", "plc-forward", "operator", "Mon 08:00-17:00 UTC", "10-20", "420 B", "12 messages", "9 would allow · 3 would deny", "engineering", "safety", "20000"]) {
    await expect(detail).toContainText(value);
  }
  await expect(detail.locator("dd").getByText("on", { exact: true })).toBeVisible();
  await page.screenshot({ path: test.info().outputPath("firewall-desktop.png"), fullPage: true });
  await page.keyboard.press("Space");
  await expect(button).toHaveAttribute("aria-expanded", "false");
  await expect(button).toBeFocused();
  await expect(detail).toHaveCount(0);
});

test("failed refresh retains inspectable rules but disables mutations", async ({ page }) => {
  await open(page);
  const row = page.locator('[id="rule-plc-read"]');
  await expect(row.getByRole("button", { name: "Edit", exact: true })).toBeEnabled();
  await expect(row.getByRole("button", { name: "Delete", exact: true })).toBeEnabled();
  await failRefresh(page);
  for (const name of ["Edit", "Delete", "Move to…"]) {
    await expect(row.getByRole("button", { name, exact: true })).toBeDisabled();
  }
  await expect(page.locator('[aria-controls="create-rule-panel"]')).toBeDisabled();
  const inspect = row.getByRole("button", { name: `Inspect rule ${rule.id}`, exact: true });
  await expect(inspect.locator("xpath=ancestor::fieldset[@disabled]")).toHaveCount(0);
  await inspect.click();
  const detail = page.getByLabel(`Details of ${rule.id}`, { exact: true });
  await expect(detail).toContainText("10.0.0.5/32");
  await expect(detail).toContainText("10-20");
  await inspect.click();
  await expect(detail).toHaveCount(0);
});

test("failed background refresh keeps editor diagnostics and dismissal available", async ({ page }) => {
  await open(page);
  await page.locator('[id="rule-plc-read"]').getByRole("button", { name: "Edit", exact: true }).click();
  await expect(page.getByRole("heading", { name: `Edit rule ${rule.id}`, exact: true })).toBeVisible();
  const editor = page.getByRole("heading", { name: `Edit rule ${rule.id}`, exact: true }).locator("../..");
  await failRefresh(page, true);
  await expect(editor.getByPlaceholder("description", { exact: true })).toBeDisabled();
  await expect(editor.getByRole("button", { name: "Save changes", exact: true })).toBeDisabled();
  for (const name of ["All saved matching values", "Technical details"]) {
    const summary = editor.getByText(name, { exact: true });
    await expect(summary.locator("xpath=ancestor::fieldset[@disabled]")).toHaveCount(0);
    await summary.click();
    await expect(summary.locator("..")).toHaveAttribute("open", "");
  }
  await expect(editor.getByText("firewall.rule.hit", { exact: true })).toBeVisible();
  await editor.getByRole("button", { name: "Close", exact: true }).click();
  await expect(page.getByRole("heading", { name: `Edit rule ${rule.id}`, exact: true })).toHaveCount(0);
});

test("failed refresh keeps creation diagnostics readable with editing disabled", async ({ page }) => {
  await open(page);
  await page.locator('[aria-controls="create-rule-panel"]').click();
  await failRefresh(page);
  const form = page.locator("#create-rule-panel");
  await expect(form.getByPlaceholder("id (e.g. mb-allow)")).toBeDisabled();
  await expect(form.getByRole("button", { name: "Create rule", exact: true })).toBeDisabled();
  const summary = form.getByText("Technical details", { exact: true });
  await expect(summary.locator("xpath=ancestor::fieldset[@disabled]")).toHaveCount(0);
  await summary.click();
  await expect(form.getByText("firewall.rule.hit", { exact: true })).toBeVisible();
});

test("failed background refresh disables an open move dialog without trapping dismissal", async ({ page }) => {
  await open(page);
  await page.locator('[id="rule-plc-read"]').getByRole("button", { name: "Move to…", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: `Move rule ${rule.id}`, exact: true });
  await expect(dialog.getByLabel("Position", { exact: true })).toBeFocused();
  await failRefresh(page, true);
  await expect(dialog.getByLabel("Position", { exact: true })).toBeDisabled();
  await expect(dialog.getByRole("button", { name: "Move", exact: true })).toBeDisabled();
  const cancel = dialog.getByRole("button", { name: "Cancel", exact: true });
  await cancel.focus();
  await page.keyboard.press("Tab");
  await expect(cancel).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
});

test("collapsed rules keep conditions, logging, shadow matches and failed coverage visible", async ({ page }) => {
  await open(page, {}, true);
  const row = page.locator('[id="rule-plc-read"]');
  for (const text of ["has conditions", "ICS Filter: modbus", "Log: on", "Shadow matches: 12 messages", "coverage unavailable"]) {
    await expect(row).toContainText(text);
  }
  await expect(page.getByText(/coverage read failed/)).toBeVisible();
  await expect(row.getByRole("button", { name: `Inspect rule ${rule.id}` })).toHaveAttribute("aria-expanded", "false");
});

test("rules precede collapsed creation and DPI; creation opens without losing a draft", async ({ page }) => {
  await open(page);
  const create = page.getByRole("button", { name: "Create rule", exact: true });
  await expect(create).toHaveAttribute("aria-expanded", "false");
  const dpi = page.getByRole("button", { name: /^DPI settings/ });
  await expect(dpi).toHaveAttribute("aria-expanded", "false");
  const ordered = await page.evaluate(() => {
    const table = document.querySelector('section[aria-label="Firewall rules"]')!;
    const create = document.querySelector('[aria-controls="create-rule-panel"]')!;
    const dpi = document.querySelector('[aria-controls="dpi-settings"]')!;
    return !!(table.compareDocumentPosition(create) & Node.DOCUMENT_POSITION_FOLLOWING) &&
      !!(create.compareDocumentPosition(dpi) & Node.DOCUMENT_POSITION_FOLLOWING);
  });
  expect(ordered).toBe(true);
  await create.click();
  await page.getByPlaceholder("id (e.g. mb-allow)").fill("new-rule");
  await page.locator('[aria-controls="create-rule-panel"]').click();
  await page.locator('[aria-controls="create-rule-panel"]').click();
  await expect(page.getByPlaceholder("id (e.g. mb-allow)")).toHaveValue("new-rule");
});

for (const saved of [
  { dpiEnabled: true },
  { dpiEnabled: false, dpiExclusions: [{ type: "ip", value: "10.0.0.5", reason: "maintenance" }] },
  { dpiEnabled: false, dpiIcsProtocols: { s7comm: false } },
  { dpiEnabled: false, dpiIcsParsing: { modbus: "strict" } },
]) {
  test(`saved DPI settings open automatically: ${JSON.stringify(saved)}`, async ({ page }) => {
    await open(page, saved);
    await expect(page.getByRole("button", { name: /^DPI settings/ })).toHaveAttribute("aria-expanded", "true");
    await expect(page.getByText("Industrial protocols", { exact: true })).toBeVisible();
    if ("dpiExclusions" in saved) await expect(page.getByText("maintenance", { exact: true })).toBeVisible();
    if ("dpiIcsProtocols" in saved) await expect(page.getByText("s7comm — unsupported", { exact: true })).toBeVisible();
  });
}

test("table notes format local times and disclose evaluation guidance by keyboard", async ({ page }) => {
  await open(page);
  const notes = page.getByRole("group", { name: "Rule table notes", exact: true });
  const timestamp = counterSince;
  const local = await page.evaluate(value => new Date(value).toLocaleString(), timestamp);
  for (const label of ["Rule counters", "Shadow counters"]) {
    const time = notes.getByRole("status", { name: label, exact: true }).locator("time");
    await expect(time).toHaveText(local);
    await expect(time).toHaveAttribute("title", timestamp);
    await expect(time).toHaveAttribute("datetime", timestamp);
  }
  const disclosure = notes.getByRole("button", { name: "How rules are evaluated", exact: true });
  await expect(disclosure).toHaveAttribute("aria-expanded", "false");
  await expect(notes.getByText(/Among enforcing rules/)).not.toBeVisible();
  await expect(notes.getByText(/Estimated allow\/block/)).not.toBeVisible();
  await disclosure.focus();
  await page.keyboard.press("Enter");
  await expect(disclosure).toBeFocused();
  await expect(disclosure).toHaveAttribute("aria-expanded", "true");
  await expect(notes.getByText(/Among enforcing rules/)).toBeVisible();
  await expect(notes.getByText(/every apply restarts them at zero/)).toBeVisible();
  await expect(notes.getByText(/Estimated allow\/block.*not full-policy predictions/)).toBeVisible();
  await page.keyboard.press("Space");
  await expect(disclosure).toHaveAttribute("aria-expanded", "false");
  await expect(disclosure).toBeFocused();
});

test("390 px stacks rules and Default with every action readable without horizontal scrolling", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await open(page, { dpiEnabled: true });
  const region = page.getByRole("region", { name: "Firewall rules" });
  const row = region.locator('[id="rule-plc-read"]');
  await expect(region.getByRole("columnheader")).toHaveCount(7);
  const inspect = row.getByRole("button", { name: `Inspect rule ${rule.id}`, exact: true });
  for (const control of [inspect, row.locator("[data-rule-id]")]) {
    expect(await control.evaluate(el => {
      const style = getComputedStyle(el);
      return (el.getBoundingClientRect().height - parseFloat(style.paddingTop) - parseFloat(style.paddingBottom) -
        parseFloat(style.borderTopWidth) - parseFloat(style.borderBottomWidth)) / parseFloat(style.lineHeight);
    })).toBeLessThanOrEqual(1);
  }
  for (const visibleRow of [row, region.getByRole("row", { name: "Default policy", exact: true })]) {
    for (const label of ["Zones", "Protocols", "Action", "Hits", "Actions"]) {
      const cell = visibleRow.locator(`[data-label="${label}"]`);
      await expect(cell).toBeVisible();
      expect(await cell.evaluate(el => {
        const box = el.getBoundingClientRect();
        return box.left >= 0 && box.right <= window.innerWidth;
      })).toBe(true);
    }
    await expect(visibleRow.locator('[data-label="Action"]').getByRole("status")).toBeVisible();
  }
  await expect(row.getByRole("button", { name: "Move to…", exact: true })).toBeVisible();
  await expect(row.getByRole("button", { name: "Edit", exact: true })).toBeEnabled();
  await expect(row.getByRole("button", { name: "Delete", exact: true })).toBeEnabled();
  await inspect.click();
  await expect(page.getByLabel(`Details of ${rule.id}`, { exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  const box = region.locator("div.overflow-x-auto");
  expect(await box.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
  await page.screenshot({ path: test.info().outputPath("firewall-mobile.png"), fullPage: true });
});

test("a failed settings read does not claim DPI is disabled", async ({ page }) => {
  await open(page, {}, false, true);
  const dpi = page.locator("section").filter({ has: page.getByRole("heading", { name: "Deep Packet Inspection", exact: true }) });
  await expect(dpi.getByText("Unknown", { exact: true })).toBeVisible();
  await expect(dpi.getByText("Disabled", { exact: true })).toHaveCount(0);
  await expect(dpi.getByRole("button", { name: "Toggle DPI", exact: true })).toBeDisabled();
  await expect(page.getByRole("alert").filter({ hasText: "Configuration unavailable." })).toBeVisible();
});
