import { expect, test, type Page } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import { mockLearner, openDataset } from "./fixtures/learner";

const epoch = "0123456789abcdef";
const token = (n: number) => `${epoch}.${n}`;
const shots = process.env.CAS_SCREENSHOTS_DIR ?? "test-results/cas";

async function mockConfig(page: Page, state = { counter: 1, hostname: "initial", offline: false }) {
  const writes: { path: string; revision: string | undefined; body: unknown }[] = [];
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async route => {
    const req = route.request();
    const path = new URL(req.url()).pathname.replace("/api/v1", "");
    const headers = { "X-Containd-Revision": token(state.counter) };
    if (path.startsWith("/auth/")) return route.fulfill({ json: { id: "admin", role: "admin" } });
    if (req.method() === "GET") {
      if (state.offline) return route.fulfill({ status: 503, json: { error: "offline" } });
      const config = { system: { hostname: state.hostname } };
      return route.fulfill({ headers, json: path === "/config/diff" ? {
        pendingConfirm: null, changed: true, changedSections: ["system"], running: { system: { hostname: "running" } }, candidate: config,
      } : path === "/config/backups" ? [] : {} });
    }
    const body = req.postDataJSON(); // Read before recording or unblocking tests.
    const revision = req.headers()["x-containd-if-revision"];
    writes.push({ path, revision, body });
    if (revision !== token(state.counter)) return route.fulfill({ status: 412, json: {
      error: "configuration changed since it was read", code: "config_revision_mismatch", currentRevision: token(state.counter),
    } });
    if (path === "/config/candidate") state.hostname = body.system.hostname;
    state.counter++;
    return route.fulfill({ headers: { "X-Containd-Revision": token(state.counter), "X-Containd-Config": path.includes("commit") ? "committed" : "staged" }, json: { status: "ok" } });
  });
  return { state, writes };
}

test("two views cannot silently overwrite; 412 keeps JSON and requires a second Save after Keep", async ({ page, context }) => {
  const { state, writes } = await mockConfig(page);
  const other = await context.newPage();
  const second = await mockConfig(other, state);
  await page.goto("/config/?tab=candidate");
  await other.goto("/config/?tab=candidate");
  const editor = page.getByRole("textbox", { name: "Staged config JSON" });
  const otherEditor = other.getByRole("textbox", { name: "Staged config JSON" });
  await expect(editor).toContainText("initial");
  await expect(otherEditor).toContainText("initial");
  await editor.fill(JSON.stringify({ system: { hostname: "mine" } }));
  await otherEditor.fill(JSON.stringify({ system: { hostname: "theirs" } }));
  await other.getByRole("button", { name: "Save staged config", exact: true }).click();
  await expect.poll(() => second.writes.length).toBe(1);
  // Background refresh must not advance this dirty draft's base.
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:staged")));
  await expect(editor).toHaveValue(JSON.stringify({ system: { hostname: "mine" } }));
  await page.getByRole("button", { name: "Save staged config", exact: true }).click();
  await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toBeVisible();
  expect(writes[0].revision).toBe(token(1));
  await expect(page.getByText("Failed to save candidate:", { exact: false })).toHaveCount(0);
  await mkdir(shots, { recursive: true });
  for (const width of [1280, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await page.screenshot({ path: `${shots}/conflict-${width}.png`, fullPage: true, animations: "disabled" });
  }
  await page.getByRole("button", { name: "Keep my edits", exact: true }).click();
  await expect(page.getByText("Based on an older view — review, then save again.", { exact: true })).toBeVisible();
  expect(writes).toHaveLength(1);
  await expect(page.getByText("Failed to save candidate:", { exact: false })).toHaveCount(0);
  await page.getByRole("button", { name: "Save staged config", exact: true }).click();
  await expect.poll(() => writes.length).toBe(2);
  expect(writes[1].revision).toBe(token(2));
  expect(state.hostname).toBe("mine");
  await other.close();
});

test("status bar only opens review; commit dialog freezes displayed diff and revision", async ({ page }) => {
  const { state, writes } = await mockConfig(page);
  await page.goto("/config/?tab=candidate");
  await expect(page.getByRole("link", { name: "Review diff", exact: true })).toBeVisible();
  await mkdir(shots, { recursive: true });
  for (const width of [1280, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await page.screenshot({ path: `${shots}/status-review-${width}.png`, fullPage: true, animations: "disabled" });
  }
  await page.getByRole("link", { name: "Review diff", exact: true }).click();
  await expect(page.getByRole("region", { name: "System changes" })).toContainText("initial");
  for (const width of [1280, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await page.screenshot({ path: `${shots}/diff-review-${width}.png`, fullPage: true, animations: "disabled" });
  }
  await page.getByRole("button", { name: "Commit", exact: true }).click();
  for (const width of [1280, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await page.screenshot({ path: `${shots}/commit-review-${width}.png`, fullPage: true, animations: "disabled" });
  }
  state.counter++;
  state.hostname = "not-reviewed";
  const response = page.waitForResponse("**/api/v1/config/diff");
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:staged")));
  await (await response).finished();
  await expect(page.getByRole("region", { name: "System changes" })).not.toContainText("not-reviewed");
  await page.getByRole("dialog").getByRole("button", { name: "Commit", exact: true }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0]).toMatchObject({ path: "/config/commit", revision: token(1) });
  await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toBeVisible();
  await expect(page.getByText("Commit failed:", { exact: false })).toHaveCount(0);
  await page.getByRole("button", { name: "Reload", exact: true }).click();
  await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Commit failed:", { exact: false })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "System changes" })).toContainText("not-reviewed");
  await page.getByRole("button", { name: "Commit", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Commit", exact: true }).click();
  await expect.poll(() => writes.length).toBe(2);
  expect(writes[1].revision).toBe(token(2));
});

test("unavailable revision or diff never enables commit", async ({ page }) => {
  await mockConfig(page);
  await page.route("**/api/v1/config/diff", route => route.fulfill({ json: { pendingConfirm: null, changed: true, changedSections: [], running: {}, candidate: {} } }));
  await page.goto("/config/?tab=diff");
  await expect(page.getByText("Unable to load configuration changes. Use Refresh to try again.", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Commit", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Commit-confirmed", exact: true })).toBeDisabled();
});

test("learner preserves selections and original receipt through conflict and reviewed retry", async ({ page }) => {
  await mockLearner(page);
  let counter = 1;
  const attempts: { revision?: string; body: unknown }[] = [];
  await page.route("**/api/v1/config/diff", route => route.fulfill({ headers: { "X-Containd-Revision": token(counter) }, json: {
    pendingConfirm: null, changed: true, changedSections: ["firewall"], running: {}, candidate: {},
  } }));
  await page.route("**/api/v1/learn/apply", async route => {
    const body = route.request().postDataJSON();
    const revision = route.request().headers()["x-containd-if-revision"];
    attempts.push({ revision, body });
    if (attempts.length === 1) return route.fulfill({ status: 412, json: { error: "changed", code: "config_revision_mismatch", currentRevision: token(counter) } });
    return route.fulfill({ headers: { "X-Containd-Revision": token(++counter), "X-Containd-Config": "staged" }, json: { staged: true } });
  });
  await openDataset(page);
  await page.getByLabel("Select modbus-1", { exact: true }).check();
  await page.getByRole("button", { name: "Refresh suggestions", exact: true }).click();
  await expect(page.getByLabel("Select modbus-1", { exact: true })).toBeChecked();
  counter++;
  await page.getByRole("button", { name: "Stage 1 selected", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Stage", exact: true }).click();
  await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Select modbus-1", { exact: true })).toBeChecked();
  await expect(page.getByRole("button", { name: "Retry same staging request" })).toBeDisabled();
  await page.getByRole("button", { name: "Keep my edits", exact: true }).click();
  expect(attempts).toHaveLength(1);
  await page.getByRole("button", { name: "Retry same staging request" }).click();
  await expect.poll(() => attempts.length).toBe(2);
  expect(attempts[0].revision).toBe(token(1));
  expect(attempts[1].revision).toBe(token(2));
  expect(attempts[1].body).toEqual(attempts[0].body);
});

test("a selected config import retains its destination base across refresh and conflict", async ({ page }) => {
  const { state, writes } = await mockConfig(page);
  await page.goto("/config/");
  await expect(page.getByRole("link", { name: "Review diff", exact: true })).toBeVisible();
  await page.locator('input[type="file"]').first().setInputFiles({ name: "config.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify({ system: { hostname: "imported" } })) });
  state.counter++;
  const response = page.waitForResponse("**/api/v1/config/diff");
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:staged")));
  await (await response).finished();
  await page.getByRole("button", { name: "Restore", exact: true }).click();
  await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toBeVisible();
  expect(writes[0].revision).toBe(token(1));
  await page.getByRole("button", { name: "Keep my edits", exact: true }).click();
  expect(writes).toHaveLength(1);
  await page.getByRole("button", { name: "Restore", exact: true }).click();
  await expect.poll(() => writes.length).toBe(2);
  expect(writes[1]).toMatchObject({ path: "/config/import", revision: token(2), body: { system: { hostname: "imported" } } });
});

test("commit-confirmed remains bound to the diff visible when its dialog opened", async ({ page }) => {
  const { state, writes } = await mockConfig(page);
  await page.goto("/config/?tab=diff");
  await expect(page.getByRole("region", { name: "System changes" })).toContainText("initial");
  await page.getByRole("button", { name: "Commit-confirmed", exact: true }).click();
  state.counter++;
  state.hostname = "unreviewed";
  const response = page.waitForResponse("**/api/v1/config/diff");
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:staged")));
  await (await response).finished();
  await expect(page.getByRole("region", { name: "System changes" })).not.toContainText("unreviewed");
  await page.getByRole("dialog").getByRole("button", { name: "Start timer", exact: true }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0]).toMatchObject({ path: "/config/commit_confirmed", revision: token(1) });
  await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toBeVisible();
  await expect(page.getByText("Commit-confirmed failed:", { exact: false })).toHaveCount(0);
});

test("428 keeps the draft and requires Reload rather than inventing a revision", async ({ page }) => {
  await mockConfig(page);
  await page.route("**/api/v1/config/candidate", route => route.fulfill({ status: 428, json: { error: "arbitrary text", code: "config_revision_required" } }));
  await page.goto("/config/?tab=candidate");
  const editor = page.getByRole("textbox", { name: "Staged config JSON" });
  await expect(editor).toContainText("initial");
  const raw = '{"system":{"hostname":"mine"}}';
  await editor.fill(raw);
  await page.getByRole("button", { name: "Save staged config", exact: true }).click();
  await expect(page.getByText("The current configuration version could not be checked. Reload before saving.", { exact: true })).toBeVisible();
  await expect(editor).toHaveValue(raw);
  await expect(page.getByRole("button", { name: "Keep my edits", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Reload", exact: true }).click();
  await expect(editor).toContainText("initial");
});

for (const persisted of [false, true]) {
  test(`learner 503 ${persisted ? "after" : "before"} persistence retries only the reviewed revision and original receipt`, async ({ page }) => {
    await mockLearner(page);
    let counter = 1;
    const attempts: { revision?: string; body: unknown }[] = [];
    await page.route("**/api/v1/config/diff", route => route.fulfill({ headers: { "X-Containd-Revision": token(counter) }, json: {
      pendingConfirm: null, changed: persisted && counter > 1, changedSections: persisted && counter > 1 ? ["firewall"] : [], running: {}, candidate: {},
    } }));
    await page.route("**/api/v1/learn/apply", async route => {
      const body = route.request().postDataJSON();
      const revision = route.request().headers()["x-containd-if-revision"];
      attempts.push({ revision, body });
      if (attempts.length === 1) {
        if (persisted) counter++;
        return route.fulfill({ status: 503, headers: persisted ? { "X-Containd-Revision": token(counter) } : {}, json: { error: "staging completion unavailable" } });
      }
      return route.fulfill({ headers: { "X-Containd-Revision": token(++counter), "X-Containd-Config": "staged" }, json: { staged: true } });
    });
    await openDataset(page);
    await page.getByLabel("Select modbus-1", { exact: true }).check();
    await page.getByRole("button", { name: "Stage 1 selected", exact: true }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Stage", exact: true }).click();
    await expect(page.getByRole("button", { name: "Retry same staging request" })).toBeDisabled();
    await expect(page.getByLabel("Select modbus-1", { exact: true })).toBeChecked();
    await page.getByRole("button", { name: "Keep my edits", exact: true }).click();
    expect(attempts).toHaveLength(1);
    await page.getByRole("button", { name: "Retry same staging request" }).click();
    await expect.poll(() => attempts.length).toBe(2);
    expect(attempts[1].body).toEqual(attempts[0].body);
    expect(attempts.map(attempt => attempt.revision)).toEqual([token(1), token(persisted ? 2 : 1)]);
  });
}

test("copy running cannot discard candidate changes hidden behind a retained JSON draft", async ({ page }) => {
  const { state, writes } = await mockConfig(page);
  await page.goto("/config/?tab=candidate");
  const editor = page.getByRole("textbox", { name: "Staged config JSON" });
  await expect(editor).toContainText("initial");
  await editor.fill('{"system":{"hostname":"mine"}}');
  state.counter++;
  state.hostname = "unseen";
  const response = page.waitForResponse("**/api/v1/config/diff");
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:staged")));
  await (await response).finished();
  await page.getByRole("button", { name: "Copy running → staged", exact: true }).click();
  await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toBeVisible();
  expect(writes[0].revision).toBe(token(1));
  expect(state.hostname).toBe("unseen");
  await expect(editor).toHaveValue('{"system":{"hostname":"mine"}}');
});

test("412 Reload discards JSON edits and adopts a fresh server snapshot", async ({ page }) => {
  const { state, writes } = await mockConfig(page);
  await page.goto("/config/?tab=candidate");
  const editor = page.getByRole("textbox", { name: "Staged config JSON" });
  await expect(editor).toContainText("initial");
  await editor.fill('{"system":{"hostname":"mine"}}');
  state.hostname = "theirs";
  state.counter++;
  await page.getByRole("button", { name: "Save staged config", exact: true }).click();
  await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Reload", exact: true }).click();
  await expect(editor).toContainText("theirs");
  expect(writes).toHaveLength(1);
  await editor.fill('{"system":{"hostname":"reviewed"}}');
  await page.getByRole("button", { name: "Save staged config", exact: true }).click();
  await expect.poll(() => state.counter).toBe(3);
  expect(writes[1].revision).toBe(token(2));
});

test("Confirm and Rollback are disabled without a diff revision", async ({ page }) => {
  await mockConfig(page);
  await page.route("**/api/v1/config/diff", route => route.fulfill({ json: { pendingConfirm: null, changed: true, changedSections: [], running: {}, candidate: {} } }));
  await page.goto("/config/?tab=diff");
  await expect(page.getByRole("button", { name: "Confirm", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Rollback", exact: true })).toBeDisabled();
});

test("rollback holds the displayed diff and the revision captured when its dialog opens", async ({ page }) => {
  const { state, writes } = await mockConfig(page);
  await page.goto("/config/?tab=diff");
  await expect(page.getByRole("region", { name: "System changes" })).toContainText("initial");
  await page.getByRole("button", { name: "Rollback", exact: true }).click();
  state.counter++;
  state.hostname = "not-reviewed";
  const response = page.waitForResponse("**/api/v1/config/diff");
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:staged")));
  await (await response).finished();
  await expect(page.getByRole("region", { name: "System changes" })).not.toContainText("not-reviewed");
  await page.getByRole("dialog").getByRole("button", { name: "Rollback", exact: true }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0]).toMatchObject({ path: "/config/rollback", revision: token(1) });
});

test("an uncertain learner request still requires review after an unavailable destination recovers", async ({ page }) => {
  await mockLearner(page);
  let offline = false;
  await page.route("**/api/v1/config/diff", route => offline
    ? route.fulfill({ status: 503, json: { error: "unavailable" } })
    : route.fulfill({ headers: { "X-Containd-Revision": token(1) }, json: { pendingConfirm: null, changed: false, changedSections: [], running: {}, candidate: {} } }));
  await page.route("**/api/v1/learn/apply", async route => {
    route.request().postDataJSON();
    offline = true;
    await route.fulfill({ status: 503, json: { error: "completion uncertain" } });
  });
  await openDataset(page);
  await page.getByLabel("Select modbus-1", { exact: true }).check();
  await page.getByRole("button", { name: "Stage 1 selected", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Stage", exact: true }).click();
  await expect(page.getByText("Destination candidate: unavailable", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry same staging request" })).toBeDisabled();
  offline = false;
  await page.getByRole("button", { name: "Refresh suggestions", exact: true }).click();
  await expect(page.getByRole("button", { name: "Keep my edits", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry same staging request" })).toBeDisabled();
  await page.getByRole("button", { name: "Keep my edits", exact: true }).click();
  await expect(page.getByRole("button", { name: "Retry same staging request" })).toBeEnabled();
});
