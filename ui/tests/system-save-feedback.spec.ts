import { expect, test, type Page, type Route } from "@playwright/test";

// User management and the AV service page show that a save is in flight and
// confirm it when it lands. A user action disables its own button until the
// server answers, so a second click cannot submit twice; a server error shows
// its message.

const admin = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };
const alice = { id: "u-alice", username: "alice", firstName: "Alice", lastName: "Ng", email: "alice@example.com", role: "view" };
// Carol must set up MFA within her grace period; Dave has MFA enabled.
const carol = { id: "u-carol", username: "carol", role: "view", mfaRequired: true, mfaEnabled: false, mfaGraceUntil: "2099-01-01T00:00:00Z" };
const dave = { id: "u-dave", username: "dave", role: "admin", mfaEnabled: true };

type Gate = { release: () => void; requests: { method: string; path: string; body: unknown }[] };

/**
 * Mocks the API. Writes to `held` paths wait for gate.release(), so a test
 * can look at the page while the request is in flight; `fail` paths answer
 * 400 with the given error.
 */
async function mockAPI(page: Page, options: { held?: string[]; fail?: Record<string, string> } = {}): Promise<Gate> {
  let release!: () => void;
  const released = new Promise<void>((resolve) => { release = resolve; });
  const gate: Gate = { release, requests: [] };
  let users: Record<string, unknown>[] = [admin, alice, carol, dave];
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route: Route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const method = request.method();
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") {
      await route.fulfill({ json: admin });
      return;
    }
    if (method === "GET") {
      const body = path === "/api/v1/users" ? users
        : path === "/api/v1/config/diff" ? { changed: false, changedSections: [] }
          : path === "/api/v1/services/av" ? { enabled: true, mode: "clamav", failPolicy: "open" }
            : path === "/api/v1/services/dns" ? { enabled: true, listenPort: 53, upstreamServers: ["192.0.2.53"] }
            : path === "/api/v1/services/av/defs" ? { path: "/data/clamav", files: [], definitions: [] }
              : path === "/api/v1/services/status" ? { av: { available: false, error: "engine unavailable" } }
                : {};
      await route.fulfill({ json: body });
      return;
    }
    gate.requests.push({ method, path, body: request.postDataJSON() });
    if (options.held?.includes(path)) await released;
    if (options.fail?.[path]) {
      await route.fulfill({ status: 400, json: { error: options.fail[path] } });
      return;
    }
    if (path === "/api/v1/users" && method === "POST") {
      const created = { ...(request.postDataJSON() as object), id: "u-bob" };
      users = [...users, created];
      await route.fulfill({ json: created });
      return;
    }
    if (path === `/api/v1/users/${alice.id}` && method === "DELETE") {
      users = users.filter((u) => u.id !== alice.id);
      await route.fulfill({ status: 204, body: "" });
      return;
    }
    if (path === "/api/v1/services/av" || path === "/api/v1/services/dns") {
      await route.fulfill({ json: request.postDataJSON() });
      return;
    }
    await route.fulfill({ json: { status: "ok" } });
  });
  return gate;
}

async function openUsers(page: Page) {
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/users");
  await page.goto("/system/users/");
  await loaded;
}

const toast = (page: Page) => page.getByRole("status", { name: "Notifications" });
const row = (page: Page, username: string) =>
  page.getByRole("row").filter({ has: page.getByRole("cell", { name: username, exact: true }) });

test("creating a user disables the button while it saves, then confirms", async ({ page }) => {
  const gate = await mockAPI(page, { held: ["/api/v1/users"] });
  await openUsers(page);
  await page.getByRole("button", { name: "Add User" }).click();
  await page.getByPlaceholder("username").fill("bob");
  await page.getByPlaceholder("password").fill("correct horse battery");
  await page.getByRole("button", { name: "Create user" }).click();

  const busy = page.getByRole("button", { name: "Creating…" });
  await expect(busy).toBeDisabled();
  await expect(page.getByRole("status", { name: "Save state" })).toHaveText("State: saving…");
  await busy.click({ force: true });
  gate.release();

  await expect(toast(page)).toContainText("User bob created.");
  await expect(page.getByRole("status", { name: "Save state" })).toHaveText("State: saved.");
  await expect(page.getByRole("button", { name: "Create user" })).toBeEnabled();
  expect(gate.requests.filter((r) => r.method === "POST")).toHaveLength(1);
});

test("a refused create shows the server's error", async ({ page }) => {
  await mockAPI(page, { fail: { "/api/v1/users": "username already exists" } });
  await openUsers(page);
  await page.getByRole("button", { name: "Add User" }).click();
  await page.getByPlaceholder("username").fill("alice");
  await page.getByPlaceholder("password").fill("correct horse battery");
  await page.getByRole("button", { name: "Create user" }).click();
  await expect(page.getByText("username already exists").first()).toBeVisible();
  await expect(toast(page)).toContainText("username already exists");
  await expect(page.getByRole("status", { name: "Save state" })).toHaveText("State: error");
  await expect(page.getByRole("button", { name: "Create user" })).toBeEnabled();
});

test("saving an edit disables Save until the server answers", async ({ page }) => {
  const gate = await mockAPI(page, { held: [`/api/v1/users/${alice.id}`] });
  await openUsers(page);
  await row(page, "alice").getByRole("button", { name: "Edit", exact: true }).click();
  await row(page, "alice").getByPlaceholder("first name").fill("Alicia");
  await row(page, "alice").getByRole("button", { name: "Save", exact: true }).click();
  await expect(row(page, "alice").getByRole("button", { name: "Saving…" })).toBeDisabled();
  gate.release();
  await expect(toast(page)).toContainText("User saved.");
  await expect(row(page, "alice").getByRole("button", { name: "Edit", exact: true })).toBeVisible();
  expect(gate.requests).toEqual([
    { method: "PATCH", path: `/api/v1/users/${alice.id}`, body: { firstName: "Alicia", lastName: "Ng", email: "alice@example.com", role: "view" } },
  ]);
});

test("a refused edit keeps the editor open and shows the error", async ({ page }) => {
  await mockAPI(page, { fail: { [`/api/v1/users/${alice.id}`]: "invalid email" } });
  await openUsers(page);
  await row(page, "alice").getByRole("button", { name: "Edit", exact: true }).click();
  await row(page, "alice").getByRole("button", { name: "Save", exact: true }).click();
  await expect(toast(page)).toContainText("invalid email");
  await expect(row(page, "alice").getByRole("button", { name: "Save", exact: true })).toBeEnabled();
});

test("resetting a password disables Set Password while it saves", async ({ page }) => {
  const path = `/api/v1/users/${alice.id}/password`;
  const gate = await mockAPI(page, { held: [path] });
  await openUsers(page);
  await row(page, "alice").getByRole("button", { name: "Reset password" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByPlaceholder("Enter new password").fill("new long passphrase");
  await dialog.getByRole("button", { name: "Set Password" }).click();
  await expect(dialog.getByRole("button", { name: "Setting…" })).toBeDisabled();
  gate.release();
  await expect(toast(page)).toContainText("Password set for alice.");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(gate.requests).toEqual([{ method: "POST", path, body: { password: "new long passphrase" } }]);
});

test("a refused password keeps the dialog open with the error", async ({ page }) => {
  await mockAPI(page, { fail: { [`/api/v1/users/${alice.id}/password`]: "password too short" } });
  await openUsers(page);
  await row(page, "alice").getByRole("button", { name: "Reset password" }).click();
  await page.getByRole("dialog").getByPlaceholder("Enter new password").fill("x");
  await page.getByRole("dialog").getByRole("button", { name: "Set Password" }).click();
  await expect(toast(page)).toContainText("password too short");
  await expect(page.getByRole("dialog").getByRole("button", { name: "Set Password" })).toBeEnabled();
});

test("deleting a user disables Delete until the server answers", async ({ page }) => {
  const gate = await mockAPI(page, { held: [`/api/v1/users/${alice.id}`] });
  await openUsers(page);
  await row(page, "alice").getByRole("button", { name: "Delete", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Delete", exact: true }).click();
  await expect(row(page, "alice").getByRole("button", { name: "Deleting…" })).toBeDisabled();
  gate.release();
  await expect(toast(page)).toContainText("User alice deleted.");
  await expect(row(page, "alice")).toHaveCount(0);
  expect(gate.requests.filter((r) => r.method === "DELETE")).toHaveLength(1);
});

test("a refused delete keeps the user and shows the error", async ({ page }) => {
  await mockAPI(page, { fail: { [`/api/v1/users/${alice.id}`]: "cannot delete the last admin" } });
  await openUsers(page);
  await row(page, "alice").getByRole("button", { name: "Delete", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Delete", exact: true }).click();
  await expect(toast(page)).toContainText("cannot delete the last admin");
  await expect(row(page, "alice").getByRole("button", { name: "Delete", exact: true })).toBeEnabled();
});

test("saving AV settings confirms the staged change", async ({ page }) => {
  const gate = await mockAPI(page);
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/services/av");
  await page.goto("/system/services/av/");
  await loaded;
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(toast(page)).toContainText("AV settings staged — commit to apply.");
  await expect(page.getByText("State: staged — commit to apply.")).toBeVisible();
  expect(gate.requests.map((r) => r.path)).toEqual(["/api/v1/services/av"]);
});

test("a refused AV save shows the server's error", async ({ page }) => {
  await mockAPI(page, { fail: { "/api/v1/services/av": "services.av.mode must be icap or clamav" } });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/services/av");
  await page.goto("/system/services/av/");
  await loaded;
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(toast(page)).toContainText("services.av.mode must be icap or clamav");
  await expect(page.getByText("State: error")).toBeVisible();
});

for (const [label, confirmLabel, busy, username, path, success] of [
  ["Require MFA", "Require MFA", "Requiring\u2026", "alice", "/api/v1/users/u-alice/mfa/require", "MFA required for alice."],
  ["Extend grace", "Extend grace", "Extending\u2026", "carol", "/api/v1/users/u-carol/mfa/grace", "MFA grace extended for carol."],
  ["Clear MFA req", "Clear requirement", "Clearing\u2026", "carol", "/api/v1/users/u-carol/mfa/clear", "MFA requirement cleared for carol."],
  ["Disable MFA", "Disable MFA", "Disabling\u2026", "dave", "/api/v1/users/u-dave/mfa/disable", "MFA disabled for dave."],
] as const) {
  test(`${label} disables its button while it saves, then confirms`, async ({ page }) => {
    const gate = await mockAPI(page, { held: [path] });
    await openUsers(page);
    await row(page, username).getByRole("button", { name: label, exact: true }).click();
    await page.getByRole("dialog").getByRole("button", { name: confirmLabel, exact: true }).click();
    await expect(row(page, username).getByRole("button", { name: busy })).toBeDisabled();
    await expect(page.getByRole("status", { name: "Save state" })).toHaveText("State: saving\u2026");
    gate.release();
    await expect(toast(page)).toContainText(success);
    await expect(page.getByRole("status", { name: "Save state" })).toHaveText("State: saved.");
    expect(gate.requests).toEqual([{ method: "POST", path, body: {} }]);
  });
}

test("a refused MFA action shows the server's error and re-enables its button", async ({ page }) => {
  await mockAPI(page, { fail: { "/api/v1/users/u-alice/mfa/require": "user has no email for MFA notices" } });
  await openUsers(page);
  await row(page, "alice").getByRole("button", { name: "Require MFA", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Require MFA", exact: true }).click();
  await expect(toast(page)).toContainText("user has no email for MFA notices");
  await expect(page.getByText("user has no email for MFA notices").first()).toBeVisible();
  await expect(row(page, "alice").getByRole("button", { name: "Require MFA", exact: true })).toBeEnabled();
});

test("a service page's Save is disabled in flight and a double click saves once", async ({ page }) => {
  const gate = await mockAPI(page, { held: ["/api/v1/services/dns"] });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/services/dns");
  await page.goto("/system/services/dns/");
  await loaded;
  await page.getByRole("button", { name: "Save", exact: true }).dblclick();
  const busy = page.getByRole("button", { name: "Saving\u2026" });
  await expect(busy).toBeDisabled();
  await expect(page.getByRole("status", { name: "Save state" })).toHaveText("State: saving\u2026");
  gate.release();
  await expect(toast(page)).toContainText("DNS settings staged \u2014 commit to apply.");
  await expect(page.getByRole("button", { name: "Save", exact: true })).toBeEnabled();
  expect(gate.requests.filter((r) => r.path === "/api/v1/services/dns")).toHaveLength(1);
});
