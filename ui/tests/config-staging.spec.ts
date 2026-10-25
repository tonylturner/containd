import { expect, test, type Page } from "@playwright/test";
import type { ConfigDiff } from "../lib/api-config";

async function setup(page: Page) {
  const state = { dirty: false, offline: false, reject: false, reads: 0, writes: [] as { path: string; body: any }[], zones: [{ name: "lan" }], ids: { enabled: false, rules: [{ id: "keep-me", name: "Keep me", type: "suricata", enabled: true }] } };
  await page.route("**/api/v1/**", async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname.replace(/^.*\/api\/v1/, "");
    if (req.method() !== "GET") {
      const body = req.postDataJSON();
      state.writes.push({ path, body });
      if (state.reject) return route.fulfill({ status: 400, json: { error: "mutation rejected" } });
      const headers: Record<string, string> = {};
      if (path.startsWith("/config/commit")) {
        state.dirty = false;
        headers["X-Containd-Config"] = "committed";
        headers["X-Containd-Warnings"] = "test apply warning";
      }
      else if (path === "/zones") { state.dirty = true; state.zones.push(body); }
      else if (path === "/ids/rules") {
        state.dirty = true;
        state.ids = { ...body, rules: body.rules.map((rule: any) => ({ ...rule, name: "Server-normalized rule" })) };
      }
      else if (path === "/pcap/config") state.dirty = true;
      if (["/zones", "/ids/rules", "/pcap/config"].includes(path)) headers["X-Containd-Config"] = "staged";
      return route.fulfill({ headers, json: path === "/ids/rules" ? state.ids : body ?? {} });
    }
    if (path === "/config/diff") {
      state.reads++;
      return route.fulfill(state.offline ? { status: 503, json: { error: "offline" } } : { json: { changed: state.dirty, changedSections: state.dirty ? ["zones"] : [], running: {}, candidate: state.dirty ? { zones: state.zones } : {}, idsBank: { running: { count: 0, sha256: "empty" }, candidate: { count: 0, sha256: "empty" } } } });
    }
    const data: Record<string, unknown> = {
      "/auth/me": { id: "admin-1", username: "containd", role: "admin" },
      "/auth/session": { id: "admin-1", username: "containd", role: "admin" },
      "/zones": state.zones,
      "/ids/rules": state.ids,
      "/ids/sources": [],
      "/security/conduits": {},
      "/interfaces": [{ name: "lan", device: "eth0", zone: "lan" }],
      "/interfaces/state": [],
      "/pcap/config": { enabled: false, interfaces: ["lan"], snaplen: 65535 },
      "/pcap/status": { running: false },
      "/pcap/list": [],
      "/system/info": {},
      "/config/backups": [],
    };
    await route.fulfill({ json: data[path] ?? {} });
  });
  return state;
}

const pending = "Uncommitted changes — not active until you commit.";

test("successful zone mutation immediately refreshes global status; commit refreshes editors", async ({ page }) => {
  const state = await setup(page);
  await page.goto("/zones/");
  await expect.poll(() => state.reads).toBeGreaterThan(0);
  await expect(page.getByText(pending, { exact: true })).toHaveCount(0);
  await page.getByPlaceholder("name (e.g. ot)").fill("newzone");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByText(pending, { exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "newzone", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Commit", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Commit", exact: true }).click();
  await expect(page.getByText(pending, { exact: true })).toHaveCount(0);
  expect(state.writes.map((w) => w.path)).toEqual(["/zones", "/config/commit"]);
});

test("failed mutation never shows pending; failed diff shows unknown, never clean", async ({ page }) => {
  const state = await setup(page);
  state.reject = true;
  await page.goto("/zones/");
  await page.getByPlaceholder("name (e.g. ot)").fill("newzone");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByText("mutation rejected", { exact: true })).toBeVisible();
  await expect(page.getByText(pending, { exact: true })).toHaveCount(0);
  state.offline = true;
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:staged")));
  await expect(page.getByText("Configuration status unknown — unable to check pending changes.")).toBeVisible();
  state.offline = false;
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.getByText("Configuration status unknown — unable to check pending changes.")).toHaveCount(0);
});

test("editors consume both events and status bar supports commit-confirmed", async ({ page }) => {
  const state = await setup(page);
  await page.goto("/zones/");
  for (const event of ["containd:config:staged", "containd:config:committed"]) {
    const name = `zone-${event.endsWith("staged") ? "stage" : "commit"}`;
    state.zones.push({ name });
    state.dirty = true;
    await page.evaluate((type) => window.dispatchEvent(new CustomEvent(type)), event);
    await expect(page.getByRole("cell", { name, exact: true })).toBeVisible();
  }
  await page.getByRole("button", { name: "Commit-confirmed", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Commit-confirmed", exact: true }).click();
  await expect(page.getByRole("link", { name: "Confirm / rollback" })).toBeVisible();
  expect(state.writes.at(-1)).toEqual({ path: "/config/commit_confirmed", body: { ttl_seconds: 60 } });
});

test("two IDS saves retain the returned rule bank", async ({ page }) => {
  const state = await setup(page);
  await page.goto("/ids/");
  await expect(page.getByText("keep-me", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("IDS rules staged — commit to apply.", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => state.writes.filter((w) => w.path === "/ids/rules").length).toBe(2);
  expect(state.writes[1].body.rules).toEqual(state.ids.rules);
  expect(state.writes[1].body.rules[0].name).toBe("Server-normalized rule");
});

test("capture start is immediate and does not persist defaults; saving defaults stages", async ({ page }) => {
  const state = await setup(page);
  await page.goto("/dataplane/");
  await page.getByRole("button", { name: "Start capture now", exact: true }).click();
  await expect.poll(() => state.writes.length).toBe(1);
  expect(state.writes[0].path).toBe("/pcap/start");
  await expect(page.getByText(pending, { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Save PCAP defaults", exact: true }).click();
  await expect(page.getByText(pending, { exact: true })).toBeVisible();
  expect(state.writes[1].path).toBe("/pcap/config");
});

test("PCAP generation stages one rule per request, including partial failure feedback", async ({ page }) => {
  const state = await setup(page);
  const rules = [{ id: "generated-1", action: "ALLOW" }, { id: "generated-2", action: "DENY" }];
  await page.route("**/api/v1/pcap/list", (route) => route.fulfill({ json: [{ name: "example.pcap", interface: "eth0", sizeBytes: 20, createdAt: "2026-10-25T12:00:00Z" }] }));
  await page.route("**/api/v1/pcap/analyze/example.pcap", (route) => route.fulfill({ json: { rules, profiles: [], eventSummary: {}, stats: { packetCount: 1, duration: 1000, flows: [], protocols: {} } } }));
  await page.route("**/api/v1/firewall/rules", async (route) => {
    const body = route.request().postDataJSON();
    state.writes.push({ path: "/firewall/rules", body });
    if (body.id === "generated-2") return route.fulfill({ status: 400, json: { error: "second rule rejected" } });
    state.dirty = true;
    await route.fulfill({ headers: { "X-Containd-Config": "staged" }, json: body });
  });
  await page.goto("/pcap/");
  await page.getByLabel("Existing PCAP Files").getByRole("button", { name: "Analyze", exact: true }).click();
  await page.getByRole("button", { name: "Stage 2 Rule(s)", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Stage", exact: true }).click();
  await expect(page.getByText("1 rule(s) staged — commit to apply. Remaining rules failed: second rule rejected", { exact: true })).toBeVisible();
  expect(state.writes.map((w) => w.body)).toEqual(rules);
  await expect(page.getByText(pending, { exact: true })).toBeVisible();
});

test("topology surfaces failed zone patches without optimistic target changes", async ({ page }) => {
  const state = await setup(page);
  state.zones = [{ name: "MixedCase" }, { name: "wan" }];
  state.reject = true;
  await page.route("**/api/v1/security/conduits", (route) => route.fulfill({ json: { "mixedcase→wan": { state: "allow", ids: "none", traffic: 0, proto: [], gaps: [] } } }));
  await page.goto("/topology/");
  await page.getByRole("button", { name: "SECURITY", exact: true }).click();
  await page.getByText("ALLOW", { exact: true }).click();
  await page.getByRole("button", { name: "Stage MIXEDCASE target SL 3", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "mutation rejected" })).toBeVisible();
  expect(state.writes.at(-1)).toEqual({ path: "/zones/MixedCase", body: { slTarget: 3 } });
  await expect(page.getByText("sl_target: 0", { exact: true })).toHaveCount(2);
  await expect(page.getByText(pending, { exact: true })).toHaveCount(0);
});

test("an event during an in-flight diff read is not lost or overwritten", async ({ page }) => {
  const state = await setup(page);
  await page.goto("/zones/");
  await expect(page.getByLabel("Zone name")).toBeVisible();
  await expect.poll(() => state.reads).toBeGreaterThan(0);
  await expect(page.getByText("Configuration status unknown — unable to check pending changes.")).toHaveCount(0);
  let reads = 0;
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => { release = resolve; });
  await page.route("**/api/v1/config/diff", async (route) => {
    reads++;
    if (reads === 1) {
      await held;
      return route.fulfill({ json: { changed: false, changedSections: [], running: {}, candidate: {} } });
    }
    return route.fulfill({ json: { changed: true, changedSections: ["zones"], running: {}, candidate: { zones: [{ name: "staged" }] } } });
  });
  try {
    await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:staged")));
    await expect.poll(() => reads).toBe(1);
    await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:committed")));
    await expect(page.getByText(pending, { exact: true })).toBeVisible();
    const response = page.waitForResponse("**/api/v1/config/diff");
    release();
    await (await response).finished();
    await page.evaluate(() => new Promise(requestAnimationFrame));
    await expect(page.getByText(pending, { exact: true })).toBeVisible();
  } finally { release(); }
});

test("failed commit preserves pending status and exposes the server error", async ({ page }) => {
  const state = await setup(page);
  state.dirty = true;
  state.reject = true;
  await page.goto("/zones/");
  await expect(page.getByText(pending, { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Commit", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Commit", exact: true }).click();
  await expect(page.getByText("mutation rejected", { exact: true })).toBeVisible();
  await expect(page.getByText(pending, { exact: true })).toBeVisible();
});


test("secret-only edits trust authoritative changed even when redacted snapshots match", async ({ page }) => {
  await setup(page);
  await page.route("**/api/v1/config/diff", (route) => route.fulfill({ json: {
    changed: true, changedSections: ["services"], running: {}, candidate: {},
    idsBank: { running: { count: 30000, sha256: "same" }, candidate: { count: 30000, sha256: "same" } },
  } }));
  await page.goto("/zones/");
  await expect(page.getByText(pending, { exact: true })).toBeVisible();
});

test("committed events clear commit-confirmed and warning notices", async ({ page }) => {
  const state = await setup(page);
  state.dirty = true;
  await page.goto("/zones/");
  await page.getByRole("button", { name: "Commit-confirmed", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Commit-confirmed", exact: true }).click();
  await expect(page.getByRole("link", { name: "Confirm / rollback" })).toBeVisible();
  await expect(page.getByText("Warning: test apply warning", { exact: true })).toBeVisible();
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:committed")));
  await expect(page.getByRole("link", { name: "Confirm / rollback" })).toHaveCount(0);
  await expect(page.getByText("Warning: test apply warning", { exact: true })).toHaveCount(0);
});

const unchangedBank = { count: 30000, sha256: "a".repeat(64) };

function configDiff(overrides: Partial<ConfigDiff> = {}): ConfigDiff {
  return {
    changed: false,
    changedSections: [],
    running: {},
    candidate: {},
    idsBank: { running: unchangedBank, candidate: unchangedBank },
    ...overrides,
  };
}

async function setupConfigReview(page: Page, diff: ConfigDiff) {
  const state = await setup(page);
  await page.route("**/api/v1/config/diff", (route) => route.fulfill(
    state.offline ? { status: 503, json: { error: "offline" } } : { json: diff },
  ));
  return state;
}

test("Config review shows a secret-only section without values or digests", async ({ page }) => {
  const redacted = { services: { wireguard: { privateKey: "" } } };
  await setupConfigReview(page, configDiff({
    changed: true, changedSections: ["services"], running: redacted, candidate: redacted,
  }));
  await page.goto("/config/?tab=diff");
  const block = page.getByRole("region", { name: "Services changes", exact: true });
  await expect(block.getByText("Secret values changed (hidden).", { exact: true })).toBeVisible();
  await expect(block).not.toContainText("privateKey");
  await expect(block).not.toContainText("SHA-256");
  await expect(block).not.toContainText(unchangedBank.sha256);
  await expect(block).not.toContainText("0 added");
  await expect(page.getByText("No differences between running and staged config.", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Commit", exact: true }).last().click();
  await expect(page.getByRole("dialog")).toContainText("1 changed block");
});

for (const bank of [
  { name: "count change", count: 30001, sha256: "b".repeat(64) },
  { name: "same-count replacement", count: 30000, sha256: "b".repeat(64) },
  { name: "empty bank", count: 0, sha256: "b".repeat(64) },
]) {
  test(`Config review shows IDS bank ${bank.name} without a bank body`, async ({ page }) => {
    await setupConfigReview(page, configDiff({
      changed: true, changedSections: ["ids"],
      running: { ids: { enabled: true } }, candidate: { ids: { enabled: true } },
      idsBank: { running: unchangedBank, candidate: bank },
    }));
    await page.goto("/config/?tab=diff");
    const block = page.getByRole("region", { name: "IDS changes", exact: true });
    await expect(block.getByText("IDS rule bank", { exact: true })).toBeVisible();
    await expect(block).toContainText("Running: 30,000 rules · SHA-256 aaaaaaaaaaaa");
    await expect(block).toContainText(`Staged: ${bank.count.toLocaleString("en-US")} rules · SHA-256 bbbbbbbbbbbb`);
    await expect(block).not.toContainText(unchangedBank.sha256);
    await expect(block).not.toContainText(bank.sha256);
    await expect(block.getByText("Secret values changed (hidden).", { exact: true })).toHaveCount(0);
    await expect(page.getByText("No differences between running and staged config.", { exact: true })).toHaveCount(0);
  });
}

test("Config review includes unknown sections and complete known top-level sections", async ({ page }) => {
  const running: ConfigDiff["running"] & Record<string, unknown> = {
    firewall: { defaultAction: "ALLOW" }, dataplane: { dpiMode: "learn" }, futureSection: { mode: "before" },
  };
  const candidate: ConfigDiff["candidate"] & Record<string, unknown> = {
    firewall: { defaultAction: "DENY" }, dataplane: { dpiMode: "enforce" }, futureSection: { mode: "after" },
  };
  await setupConfigReview(page, configDiff({
    changed: true, changedSections: ["firewall", "dataplane", "futureSection", "hiddenFuture"],
    running, candidate,
  }));
  await page.goto("/config/?tab=diff");
  const firewall = page.getByRole("region", { name: "Firewall changes", exact: true });
  await expect(firewall).toContainText('"defaultAction": "ALLOW"');
  await expect(firewall).toContainText('"defaultAction": "DENY"');
  await expect(page.getByRole("region", { name: "Data plane changes", exact: true })).toContainText('"dpiMode": "enforce"');
  const future = page.getByRole("region", { name: "futureSection changes", exact: true });
  await expect(future).toContainText('"mode": "before"');
  await expect(future).toContainText('"mode": "after"');
  await expect(page.getByRole("region", { name: "hiddenFuture changes", exact: true })).toContainText("Secret values changed (hidden).");
  await expect(page.getByRole("region", { name: / changes$/ })).toHaveCount(4);
});

test("Config review combines IDS settings lines and bank summary", async ({ page }) => {
  await setupConfigReview(page, configDiff({
    changed: true, changedSections: ["ids"],
    running: { ids: { enabled: false } }, candidate: { ids: { enabled: true } },
    idsBank: { running: unchangedBank, candidate: { count: 30001, sha256: "b".repeat(64) } },
  }));
  await page.goto("/config/?tab=diff");
  const block = page.getByRole("region", { name: "IDS changes", exact: true });
  await expect(block).toContainText('"enabled": false');
  await expect(block).toContainText('"enabled": true');
  await expect(block).toContainText("IDS rule bank");
});

test("Config review distinguishes clean, missing candidate, and failed diff reads", async ({ page }) => {
  const diff = configDiff();
  const state = await setupConfigReview(page, diff);
  await page.goto("/config/?tab=diff");
  const clean = page.getByText("No differences between running and staged config.", { exact: true });
  await expect(clean).toBeVisible();
  diff.candidate = null;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByText("No staged config to compare. Save staged changes to review them here.", { exact: true })).toBeVisible();
  state.offline = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Unable to load configuration changes." })).toBeVisible();
  await expect(clean).toHaveCount(0);
  state.offline = false;
  diff.candidate = {};
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(clean).toBeVisible();
});

test("Config candidate editor saves the omitted bank unchanged and summary uses its count", async ({ page }) => {
  const diff = configDiff({ running: { ids: { enabled: true } }, candidate: { ids: { enabled: false } } });
  const state = await setupConfigReview(page, diff);
  await page.goto("/config/?tab=candidate");
  const editor = page.getByRole("textbox", { name: "Staged config JSON", exact: true });
  await expect(editor).toHaveValue(JSON.stringify(diff.candidate, null, 2));
  await page.getByRole("button", { name: "Save staged config", exact: true }).click();
  await expect.poll(() => state.writes.length).toBe(1);
  expect(state.writes[0]).toEqual({ path: "/config/candidate", body: diff.candidate });
  expect(state.writes[0].body.ids).not.toHaveProperty("rules");
  expect(state.writes[0].body).not.toHaveProperty("idsBank");
  await page.getByRole("button", { name: "Overview", exact: true }).click();
  await expect(page.getByText("Running IDS bank: 30000 committed rules. Restores stage the candidate bank; commit promotes both.", { exact: true })).toBeVisible();
});
