import { expect, test, type Page, type Route } from "@playwright/test";

import { parseRetryAfter } from "../lib/api-request";
import { withRetryTime } from "../lib/utils";

// After repeated failed authentication codes or current passwords the server
// locks that check for the account and answers 429 with Retry-After. The UI
// shows the server's message and the time to retry, never a generic failure.
// A wrong current password or code answers 401: self-service forms show the
// server's reason and stay signed in; the login page stays generic.

type Reply = Parameters<Route["fulfill"]>[0];

const NOW = new Date("2026-10-26T10:00:00Z");
const admin = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false, mfaEnabled: true };

function locked(error: string, seconds: number) {
  return { status: 429, headers: { "Retry-After": String(seconds) }, json: { error } };
}

/** The local time the page shows for NOW plus `seconds`. */
function retryTime(page: Page, seconds: number) {
  return page.evaluate((at) => new Date(at).toLocaleTimeString(), NOW.getTime() + seconds * 1000);
}

async function openLogin(page: Page, routes: Record<string, Reply>) {
  await page.clock.setFixedTime(NOW);
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/auth/me") {
      await route.fulfill({ status: 401, json: { error: "unauthorized" } });
      return;
    }
    await route.fulfill(routes[path] ?? { json: {} });
  });
  await page.goto("/login/");
  await page.getByLabel("Username").fill("containd");
  await page.getByLabel("Password", { exact: true }).fill("correct horse");
}

test("a locked MFA code check shows the server's message and when to retry", async ({ page }) => {
  const message = "too many failed authentication codes for this account; try again in 15 minutes";
  await openLogin(page, {
    "/api/v1/auth/login": { json: { mfaRequired: true, mfaMethod: "totp", mfaChallengeToken: "challenge-1", user: admin } },
    "/api/v1/auth/login/mfa": locked(message, 900),
  });
  await page.getByRole("button", { name: "Login" }).click();
  await page.getByLabel("Authentication Code").fill("123456");
  await page.getByRole("button", { name: "Verify code" }).click();
  await expect(page.getByText(message)).toHaveText(`${message} Try again after ${await retryTime(page, 900)}.`);
});

test("a wrong MFA code stays a generic refusal", async ({ page }) => {
  await openLogin(page, {
    "/api/v1/auth/login": { json: { mfaRequired: true, mfaMethod: "totp", mfaChallengeToken: "challenge-1", user: admin } },
    "/api/v1/auth/login/mfa": { status: 401, json: { error: "invalid authentication code" } },
  });
  await page.getByRole("button", { name: "Login" }).click();
  await page.getByLabel("Authentication Code").fill("000000");
  await page.getByRole("button", { name: "Verify code" }).click();
  await expect(page.getByText("Invalid authentication code.")).toBeVisible();
  await expect(page.getByText("Try again after")).toHaveCount(0);
});

test("a rate-limited password step says when to retry", async ({ page }) => {
  const message = "too many login attempts; retry later";
  await openLogin(page, { "/api/v1/auth/login": locked(message, 60) });
  await page.getByRole("button", { name: "Login" }).click();
  await expect(page.getByText(message)).toHaveText(`${message} Try again after ${await retryTime(page, 60)}.`);
});

async function openProfile(page: Page, menuItem: "Profile" | "Change password", routes: Record<string, Reply>) {
  await page.clock.setFixedTime(NOW);
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") {
      await route.fulfill({ json: admin });
      return;
    }
    if (path === "/api/v1/zones") {
      await route.fulfill({ json: [] });
      return;
    }
    await route.fulfill(routes[path] ?? { json: {} });
  });
  await page.goto("/zones/");
  await page.getByRole("button", { name: "User menu" }).click();
  await page.getByRole("button", { name: menuItem, exact: true }).click();
  return page.getByRole("dialog");
}

test("a locked current-password check on password change says when to retry", async ({ page }) => {
  const message = "too many failed current-password checks for this account; try again in 10 minutes";
  const dialog = await openProfile(page, "Change password", { "/api/v1/auth/me/password": locked(message, 600) });
  await dialog.getByPlaceholder("Current password").fill("wrong");
  await dialog.getByPlaceholder("New password (min 8 chars)").fill("a new long passphrase");
  await dialog.getByRole("button", { name: "Update password" }).click();
  await expect(dialog.getByText(message)).toHaveText(`${message} Try again after ${await retryTime(page, 600)}.`);
});

test("a locked MFA disable says when to retry", async ({ page }) => {
  const message = "too many failed authentication codes for this account; try again in 15 minutes";
  const dialog = await openProfile(page, "Profile", { "/api/v1/auth/me/mfa/disable": locked(message, 900) });
  await dialog.getByRole("button", { name: "MFA", exact: true }).click();
  await dialog.getByLabel("Current password").fill("correct horse");
  await dialog.getByLabel("Authentication code").fill("123456");
  await dialog.getByRole("button", { name: "Disable MFA" }).click();
  await expect(dialog.getByText(message)).toHaveText(`${message} Try again after ${await retryTime(page, 900)}.`);
});

test("Retry-After is read as seconds or an HTTP date", () => {
  const now = NOW.getTime();
  const res = (value?: string) => new Response(null, { status: 429, headers: value === undefined ? {} : { "Retry-After": value } });
  expect(parseRetryAfter(res("120"), now)).toBe(120);
  expect(parseRetryAfter(res(new Date(now + 90_000).toUTCString()), now)).toBe(90);
  expect(parseRetryAfter(res(new Date(now - 5_000).toUTCString()), now)).toBe(0);
  expect(parseRetryAfter(res("soon"), now)).toBeUndefined();
  expect(parseRetryAfter(res(), now)).toBeUndefined();
  expect(withRetryTime("locked", undefined)).toBe("locked");
  expect(withRetryTime("locked", 60, now)).toBe(`locked Try again after ${new Date(now + 60_000).toLocaleTimeString()}.`);
});

test("a wrong password on the login step stays a generic refusal", async ({ page }) => {
  await openLogin(page, { "/api/v1/auth/login": { status: 401, json: { error: "invalid credentials" } } });
  await page.getByRole("button", { name: "Login" }).click();
  await expect(page.getByText("Invalid username or password.")).toBeVisible();
  await expect(page.getByText("invalid credentials")).toHaveCount(0);
});

for (const flow of ["password change", "MFA disable"] as const) {
  test(`a wrong current password on ${flow} shows the server's reason and stays signed in`, async ({ page }) => {
    const message = "current password is incorrect";
    const path = flow === "password change" ? "/api/v1/auth/me/password" : "/api/v1/auth/me/mfa/disable";
    const sessionChecks: string[] = [];
    page.on("request", (req) => {
      if (new URL(req.url()).pathname === "/api/v1/auth/me") sessionChecks.push(req.url());
    });
    const dialog = await openProfile(page, flow === "password change" ? "Change password" : "Profile", {
      [path]: { status: 401, json: { error: message } },
    });
    if (flow === "password change") {
      await dialog.getByPlaceholder("Current password").fill("wrong");
      await dialog.getByPlaceholder("New password (min 8 chars)").fill("a new long passphrase");
      await dialog.getByRole("button", { name: "Update password" }).click();
    } else {
      await dialog.getByRole("button", { name: "MFA", exact: true }).click();
      await dialog.getByLabel("Current password").fill("wrong");
      await dialog.getByLabel("Authentication code").fill("123456");
      await dialog.getByRole("button", { name: "Disable MFA" }).click();
    }
    await expect(dialog.getByText(message, { exact: true })).toBeVisible();
    await expect(dialog.getByText("Unauthorized")).toHaveCount(0);
    // The 401 still starts the session-expired check; the session is valid,
    // so it re-reads /auth/me and keeps the page.
    const before = sessionChecks.length;
    await expect.poll(() => sessionChecks.length, { timeout: 5_000 }).toBeGreaterThan(before);
    await page.waitForLoadState("networkidle");
    await expect(page).toHaveURL(/\/zones\/$/);
    await expect(dialog.getByText(message, { exact: true })).toBeVisible();
  });
}
