import { expect, test, type Page } from "@playwright/test";

const entry = {
  proto: "tcp", state: "ESTABLISHED", src: "2001:db8::1", dst: "2001:db8::2",
  sport: "41001", dport: "443", replySrc: "2001:db8:1::2", replyDst: "2001:db8:1::1",
  replySport: "8443", replyDport: "51001",
};

async function mockAPI(page: Page, options: { unavailable?: boolean; empty?: boolean; role?: string; partial?: boolean; entries?: unknown } = {}) {
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
        await route.fulfill({ status: 502, json: { error: "ctnetlink: operation not permitted" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
        return;
      }
      body = options.empty ? [] : options.entries ?? [entry];
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
    await route.fulfill({ status: 200, json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
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
  const inspect = page.getByRole("button", { name: "Inspect connection" });
  await inspect.focus();
  await page.keyboard.press("Enter");
  await expect(inspect).toHaveAttribute("aria-expanded", "true");
  await expect(inspect).toBeFocused();
  await expect(page.getByText("[2001:db8:1::2]:8443 → [2001:db8:1::1]:51001")).toBeVisible();
  await page.getByRole("button", { name: "Kill", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("A fresh source port is allowed");
  await page.getByRole("dialog").getByRole("button", { name: "Kill", exact: true }).click();
  await expect(page.getByRole("status", { name: "Connection revocation result" })).toContainText("Connection entries removed: yes (1/1)");
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
  await expect(page.getByRole("status", { name: "Connection revocation result" })).toContainText("Connection entries removed: no (0/1) — delete permission denied");
  await expect(page.getByRole("status", { name: "Connection revocation result" })).toContainText("Revocation installed: yes");
  expect(writes[0]).toMatchObject({ scope: "client-service", durationSecs: 30 });
});

test("view-only users cannot revoke connections", async ({ page }) => {
  await mockAPI(page, { role: "view" });
  await open(page);
  await expect(page.getByRole("button", { name: "Kill", exact: true })).toBeDisabled();
  await expect(page.getByLabel("Kill scope")).toHaveCount(0);
});

test("connections show the TAG labels that match them and filter by tag", async ({ page }) => {
  const tagged = { ...entry, sport: "41002", tags: ["eng-access", "ot.vendor"] };
  await mockAPI(page, { entries: [entry, tagged] });
  await open(page);
  await expect(page.getByRole("columnheader", { name: "Tags" })).toHaveCount(0);
  const row = (sport: string) => page.getByRole("row").filter({ has: page.getByRole("cell", { name: sport, exact: true }) });
  await expect(row("41002")).toContainText("Tags: 2");
  await row("41002").getByRole("button", { name: "Inspect connection" }).click();
  await expect(page.getByText("eng-access", { exact: true })).toBeVisible();
  await expect(page.getByText("ot.vendor", { exact: true })).toBeVisible();
  await row("41001").getByRole("button", { name: "Inspect connection" }).click();
  const plainDetail = row("41001").locator("xpath=following-sibling::tr[1]");
  await expect(plainDetail.getByText("Tags", { exact: true }).locator("..")).toHaveText("Tags—");
  await page.getByPlaceholder("Filter (ip, port, proto, state, tag)…").fill("ot.vendor");
  await expect(page.getByText("1 shown / 2 total")).toBeVisible();
  await expect(row("41001")).toHaveCount(0);
});

test("a malformed connection list is reported, not rendered", async ({ page }) => {
  await mockAPI(page, { entries: {} });
  await open(page);
  await expect(page.getByRole("alert", { name: "Connections error" })).toContainText("malformed connection list");
  await expect(page.getByText(/Verified empty/)).toHaveCount(0);
});

const ping = {
  proto: "icmp", src: "192.0.2.10", dst: "198.51.100.20", icmpId: "4660", icmpType: "8", icmpCode: "0",
  replySrc: "198.51.100.20", replyDst: "203.0.113.1", replyIcmpId: "7", replyIcmpType: "0", replyIcmpCode: "0",
};
const ping6 = {
  proto: "icmpv6", src: "2001:db8::10", dst: "2001:db8::20", icmpId: "0", icmpType: "128", icmpCode: "0",
  replySrc: "2001:db8::20", replyDst: "2001:db8::10", replyIcmpId: "0", replyIcmpType: "129", replyIcmpCode: "0",
};

test("ICMP rows show identifier and type in place of ports and can be killed", async ({ page }) => {
  const writes = await mockAPI(page, { entries: [ping, ping6, { proto: "47", src: "192.0.2.10", dst: "198.51.100.20" }] });
  await open(page);
  const row = page.getByRole("row").filter({ has: page.getByRole("cell", { name: "id 4660", exact: true }) });
  await expect(row.getByRole("cell", { name: "type 8 code 0", exact: true })).toBeVisible();
  await row.getByRole("button", { name: "Inspect connection" }).click();
  await expect(page.getByText("198.51.100.20 → 203.0.113.1 (id 7)", { exact: true })).toBeVisible();
  await expect(page.getByRole("row").filter({ has: page.getByRole("cell", { name: "47", exact: true }) }).getByRole("button", { name: "Kill", exact: true })).toBeDisabled();
  await row.getByRole("button", { name: "Kill", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("icmp 192.0.2.10 → 198.51.100.20 (id 4660)");
  await expect(page.getByRole("dialog")).toContainText("A new ICMP identifier is allowed. Matching packets are dropped.");
  await page.getByRole("dialog").getByRole("button", { name: "Kill", exact: true }).click();
  await expect(page.getByRole("status", { name: "Connection revocation result" })).toContainText("Connection entries removed: yes (1/1)");
  expect(writes).toEqual([{ proto: "icmp", src: ping.src, dst: ping.dst, icmpId: 4660, icmpType: 8, icmpCode: 0, scope: "connection", durationSecs: 60 }]);
});

test("client-service ICMPv6 kill ends the client's pings to that host", async ({ page }) => {
  const writes = await mockAPI(page, { entries: [ping6] });
  await open(page);
  await page.getByLabel("Kill scope").selectOption("client-service");
  const row = page.getByRole("row").filter({ has: page.getByRole("cell", { name: "id 0", exact: true }) });
  await expect(row.getByRole("cell", { name: "type 128 code 0", exact: true })).toBeVisible();
  await row.getByRole("button", { name: "Kill", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("all of the client's pings to that host stop");
  await page.getByRole("dialog").getByRole("button", { name: "Kill", exact: true }).click();
  await expect(page.getByRole("status", { name: "Connection revocation result" })).toContainText("Revocation installed: yes");
  expect(writes).toEqual([{ proto: "icmpv6", src: ping6.src, dst: ping6.dst, icmpId: 0, icmpType: 128, icmpCode: 0, scope: "client-service", durationSecs: 60 }]);
});

test("an ICMP row without identifier fields shows bare addresses and cannot be killed", async ({ page }) => {
  // An engine that predates ICMP identifiers lists only the addresses.
  await mockAPI(page, { entries: [{ proto: "icmp", src: "192.0.2.10", dst: "192.0.2.20", replySrc: "192.0.2.20", replyDst: "192.0.2.10" }] });
  await open(page);
  const row = page.getByRole("row").filter({ has: page.getByRole("cell", { name: "icmp", exact: true }) });
  await expect(row.getByRole("cell").filter({ hasNot: page.getByRole("button") })).toHaveText(["icmp", "—", "192.0.2.10", "—", "192.0.2.20", "—"]);
  await row.getByRole("button", { name: "Inspect connection" }).click();
  const detail = row.locator("xpath=following-sibling::tr[1]");
  for (const [label, value] of [["Mark", "—"], ["Tags", "—"], ["Assured", "no"], ["TTL", "—"], ["Reply tuple (NAT)", "192.0.2.20 → 192.0.2.10"]]) {
    await expect(detail.getByText(label, { exact: true }).locator("..")).toHaveText(`${label}${value}`);
  }
  await expect(row.getByRole("button", { name: "Kill", exact: true })).toBeDisabled();
});


test("connection inspection preserves every non-default diagnostic field and collapses by keyboard", async ({ page }) => {
  await mockAPI(page, { entries: [{ ...entry, mark: "0x20", tags: ["plant"], assured: true, timeoutSecs: 90 }] });
  await open(page);
  const inspect = page.getByRole("button", { name: "Inspect connection" });
  const detail = page.locator(`[id="${await inspect.getAttribute("aria-controls")}"]`);
  await expect(detail).toBeHidden();
  await expect(inspect.locator("..")).toContainText("Mark: 0x20");
  await expect(inspect.locator("..")).toContainText("Tags: 1");
  await inspect.focus();
  await page.keyboard.press("Enter");
  for (const [label, value] of [["Mark", "0x20"], ["Tags", "plant"], ["Assured", "yes"], ["TTL", "90s"], ["Reply tuple (NAT)", "[2001:db8:1::2]:8443 → [2001:db8:1::1]:51001"]]) {
    const field = detail.getByText(label, { exact: true }).locator("..");
    await expect(field).toBeVisible();
    await expect(field).toHaveText(`${label}${value}`);
  }
  await page.keyboard.press("Space");
  await expect(detail).toBeHidden();
  await expect(inspect).toBeFocused();
});
