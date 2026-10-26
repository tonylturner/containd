import { expect, test, type Page } from "@playwright/test";

const entry = {
  proto: "tcp", state: "ESTABLISHED", src: "2001:db8::1", dst: "2001:db8::2",
  sport: "41001", dport: "443", replySrc: "2001:db8:1::2", replyDst: "2001:db8:1::1",
  replySport: "8443", replyDport: "51001",
};

async function mockAPI(page: Page, options: { unavailable?: boolean; empty?: boolean; role?: string; partial?: boolean } = {}) {
  const writes: unknown[] = [];
  await page.addInitScript((role) => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", role);
  }, options.role ?? "admin");
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") {
      body = { id: "admin-1", username: "containd", role: options.role ?? "admin" };
    } else if (path === "/api/v1/conntrack") {
      if (options.unavailable) {
        await route.fulfill({ status: 502, json: { error: "ctnetlink: operation not permitted" } });
        return;
      }
      body = options.empty ? [] : [entry];
    } else if (path === "/api/v1/conntrack/kill") {
      const data = request.postDataJSON();
      writes.push(data);
      body = {
        scope: data.scope, matched: 1, deleted: options.partial ? 0 : 1,
        conntrackDeleted: !options.partial, deleteError: options.partial ? "delete permission denied" : undefined,
        revocationInstalled: true, blockedUntil: "2026-10-26T12:00:00Z",
        closure: "TCP reset signalled on each endpoint's next packet; closure not confirmed",
      };
    }
    await route.fulfill({ status: 200, json: body });
  });
  return writes;
}

async function open(page: Page) {
  const loaded = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/v1/conntrack");
  await page.goto("/sessions");
  await loaded;
}

test("unavailable shows backend reason, never verified empty", async ({ page }) => {
  await mockAPI(page, { unavailable: true });
  await open(page);
  await expect(page.getByRole("alert", { name: "Connections error" })).toContainText("ctnetlink: operation not permitted");
  await expect(page.getByText(/Verified empty/)).toHaveCount(0);
  await expect(page.getByText("No connections to display")).toHaveCount(0);
});

test("verified empty is a successful kernel snapshot", async ({ page }) => {
  await mockAPI(page, { empty: true });
  await open(page);
  await expect(page.getByText("Verified empty: the kernel returned no connections.")).toBeVisible();
  await expect(page.getByRole("alert", { name: "Connections error" })).toHaveCount(0);
});

test("exact kill preserves NAT tuple and reports each step", async ({ page }) => {
  const writes = await mockAPI(page);
  await open(page);
  await expect(page.getByText("[2001:db8:1::2]:8443 → [2001:db8:1::1]:51001")).toBeVisible();
  await page.getByRole("button", { name: "Kill", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("A fresh source port is allowed");
  await page.getByRole("dialog").getByRole("button", { name: "Kill", exact: true }).click();
  await expect(page.getByRole("status", { name: "Connection revocation result" })).toContainText("Conntrack deleted: yes (1/1)");
  await expect(page.getByRole("status", { name: "Connection revocation result" })).toContainText("Revocation installed: yes, until");
  await expect(page.getByRole("status", { name: "Connection revocation result" })).toContainText("closure not confirmed");
  expect(writes).toEqual([{ proto: "tcp", src: entry.src, dst: entry.dst, sport: 41001, dport: 443, scope: "connection", durationSecs: 60 }]);
});

test("client-service warns about all connections and exposes partial failure", async ({ page }) => {
  const writes = await mockAPI(page, { partial: true });
  await open(page);
  await page.getByLabel("Kill scope").selectOption("client-service");
  await page.getByLabel("Revocation seconds").fill("30");
  await page.getByRole("button", { name: "Kill", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("all of this client's connections to that service");
  await page.getByRole("dialog").getByRole("button", { name: "Kill", exact: true }).click();
  await expect(page.getByRole("status", { name: "Connection revocation result" })).toContainText("Conntrack deleted: no (0/1) — delete permission denied");
  await expect(page.getByRole("status", { name: "Connection revocation result" })).toContainText("Revocation installed: yes");
  expect(writes[0]).toMatchObject({ scope: "client-service", durationSecs: 30 });
});

test("view-only users cannot revoke connections", async ({ page }) => {
  await mockAPI(page, { role: "view" });
  await open(page);
  await expect(page.getByRole("button", { name: "Kill", exact: true })).toBeDisabled();
  await expect(page.getByLabel("Kill scope")).toHaveCount(0);
});
