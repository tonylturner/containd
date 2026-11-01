import { expect, test } from "@playwright/test";
import { isProtectionStatus } from "../lib/api-protection";
import { observation, openProtection, protectionAPI } from "./fixtures/protection-api";

test("an engine awaiting its first configuration does not imply a commit", async ({ page }) => {
  await protectionAPI(page, observation({
    state: "pending", applyId: "", installedApplyId: "",
    components: [{ name: "nft", required: true, state: "pending", reason: "awaiting configuration",
      since: "2026-10-31T12:00:00Z" }],
    effects: [],
  }));
  await openProtection(page);
  const notice = page.getByRole("status", { name: "Dataplane protection" });
  await expect(notice.locator("p").first()).toHaveText("Engine waiting for configuration");
  await expect(notice).not.toContainText("Committed");
  await expect(notice).toContainText("awaiting configuration");
  await expect(notice).toContainText("Wait for protection to finish, then check status.");
  await expect(notice.getByRole("button")).toHaveCount(0);
});

for (const bounded of [true, false]) {
  test(`pending protection ${bounded ? "with" : "without"} a retry budget`, async ({ page }) => {
    await protectionAPI(page, observation({
      state: "pending",
      components: [{ name: "nfqueue:101", required: true, state: "pending", reason: "bind pending",
        since: "2026-10-31T12:00:00Z", ...(bounded ? { attempt: 2, maxAttempts: 8 } : {}) }],
      effects: [{ traffic: "IEC 104 commands", effect: "fail_closed_drop" }],
    }));
    await openProtection(page);
    const notice = page.getByRole("status", { name: "Dataplane protection" });
    await expect(notice).toContainText("Committed — protection pending");
    await expect(notice).toContainText("IEC 104 commands is dropping (fail closed)");
    if (bounded) await expect(notice).toContainText("retry 2/8");
    else await expect(notice).not.toContainText("retry ");
    await expect(notice.getByRole("button")).toHaveCount(0);
  });
}

test("an unbounded required component does not borrow a background component's retry budget", async ({ page }) => {
  await protectionAPI(page, observation({
    state: "pending",
    components: [
      { name: "scan-gate", required: true, state: "pending", reason: "waiting for routing", since: "2026-10-31T12:00:00Z" },
      { name: "nflog", required: false, state: "pending", reason: "bind pending", since: "2026-10-31T12:00:00Z", attempt: 2, maxAttempts: 8 },
    ],
  }));
  await openProtection(page);
  const notice = page.getByRole("status", { name: "Dataplane protection" });
  await expect(notice).toContainText("Committed — protection pending");
  await expect(notice).not.toContainText("retry 2/8");
});

test("failed fail-closed and direct-queue effects are described separately", async ({ page }) => {
  await protectionAPI(page, observation({
    state: "failed", effects: [
      { traffic: "IEC 104 commands", effect: "fail_closed_drop" },
      { traffic: "Monitor traffic", effect: "not_inspected" },
    ],
  }));
  await openProtection(page);
  const notice = page.getByRole("status", { name: "Dataplane protection" });
  await expect(notice).toContainText("Configured but not protecting — IEC 104 commands is dropping (fail closed)");
  await expect(notice).toContainText("Monitor traffic is not being inspected by containd");
  await expect(notice).not.toContainText("Monitor traffic is dropping");
});

test("monitor-only failure never claims a drop", async ({ page }) => {
  await protectionAPI(page, observation({
    state: "failed", effects: [{ traffic: "Monitor IEC 104", effect: "not_inspected" }],
  }));
  await openProtection(page);
  const notice = page.getByRole("status", { name: "Dataplane protection" });
  await expect(notice).toContainText("Inspection unavailable — Monitor IEC 104 is not being inspected by containd");
  await expect(notice).not.toContainText("drop");
});

test("degraded logging names the missing evidence and offers admin retry", async ({ page }) => {
  await protectionAPI(page, observation({ state: "degraded", retryable: true }), { enforcement: "degraded" });
  await openProtection(page);
  const notice = page.getByRole("status", { name: "Dataplane protection" });
  await expect(notice).toContainText("Rule-hit logging unavailable");
  await expect(notice).toContainText("Nft policy is enforcing");
  await expect(notice.getByRole("button", { name: "Retry protection" })).toBeVisible();
});

test("viewers cannot retry a retryable failure", async ({ page }) => {
  const mock = await protectionAPI(page, observation({ state: "failed", retryable: true }), { role: "view" });
  await openProtection(page, "/firewall/");
  await expect(page.getByRole("status", { name: "Dataplane protection" })).toContainText("Configured but not protecting");
  await expect(page.getByRole("button", { name: "Retry protection" })).toHaveCount(0);
  expect(mock.retries).toEqual([]);
});

test("admin retries the exact boot/apply observation, then polls without optimistic green", async ({ page }) => {
  const failed = observation({ state: "failed", retryable: true });
  const mock = await protectionAPI(page, failed);
  mock.afterRetry = observation({ state: "pending" });
  await openProtection(page);
  const notice = page.getByRole("status", { name: "Dataplane protection" });
  await notice.getByRole("button", { name: "Retry protection" }).click();
  await expect(notice).toContainText("Committed — protection pending");
  expect(mock.retries).toEqual([{ bootId: failed.bootId, applyId: failed.applyId }]);
  expect(mock.reads).toBeGreaterThan(1);
});

test("retry accelerates a degraded observation for ten seconds without retrying automatically", async ({ page }) => {
  await page.clock.install();
  const mock = await protectionAPI(page, observation({ state: "degraded", retryable: true }));
  await openProtection(page);
  await page.clock.pauseAt(Date.now() + 1_000);
  const notice = page.getByRole("status", { name: "Dataplane protection" });
  const before = mock.reads;
  await notice.getByRole("button", { name: "Retry protection" }).click();
  await expect.poll(() => mock.reads).toBe(before + 1);
  await expect(notice).toContainText("Retry requested; checking protection.");
  for (let i = 1; i <= 5; i++) {
    await page.clock.runFor(2_000);
    await expect.poll(() => mock.reads).toBe(before + 1 + i);
  }
  await page.clock.runFor(29_000);
  expect(mock.reads).toBe(before + 6);
  await page.clock.runFor(1_000);
  await expect.poll(() => mock.reads).toBe(before + 7);
  expect(mock.retries).toHaveLength(1);
});

test("a failed retry reports the error and refreshes, without claiming recovery", async ({ page }) => {
  const mock = await protectionAPI(page, observation({ state: "failed", retryable: true }));
  mock.retryStatus = 502;
  await openProtection(page);
  const notice = page.getByRole("status", { name: "Dataplane protection" });
  await notice.getByRole("button", { name: "Retry protection" }).click();
  await expect(notice).toContainText("Retry failed: protection retry refused");
  await expect(notice).toContainText("Configured but not protecting");
  expect(mock.retries).toHaveLength(1);
  expect(mock.reads).toBeGreaterThan(1);
});

for (const code of ["protection_superseded", "protection_not_retryable"]) {
  test(`retry ${code} refreshes without replaying the request`, async ({ page }) => {
    const mock = await protectionAPI(page, observation({ state: "failed", retryable: true }));
    mock.retryStatus = 409;
    mock.retryCode = code;
    mock.afterRetry = observation({ state: "failed", retryable: false });
    await openProtection(page);
    const notice = page.getByRole("status", { name: "Dataplane protection" });
    await notice.getByRole("button", { name: "Retry protection" }).click();
    await expect(notice).toContainText(code === "protection_superseded" ? "Protection changed." : "no longer retryable");
    await expect(notice.getByRole("button")).toHaveCount(0);
    expect(mock.retries).toHaveLength(1);
    expect(mock.reads).toBeGreaterThan(1);
  });
}

test("read failure replaces protecting with unknown and removes all stale detail", async ({ page }) => {
  await page.clock.install();
  const mock = await protectionAPI(page, observation(), { enforcement: "enforcing" });
  await openProtection(page);
  await expect(page.getByRole("status", { name: "Dataplane protection" })).toHaveCount(0);
  mock.readStatus = 502;
  mock.status = { error: "engine unreachable" };
  await page.clock.runFor(30_000);
  const notice = page.getByRole("status", { name: "Dataplane protection" });
  await expect(notice).toContainText("Protection unknown");
  await expect(notice).not.toContainText("Protecting");
  await expect(notice.getByRole("button")).toHaveCount(0);
});

test("a new boot/apply replaces component detail rather than merging it", async ({ page }) => {
  await page.clock.install();
  const mock = await protectionAPI(page, observation({
    state: "pending", components: [{ name: "nfqueue:101", state: "pending", required: true,
      reason: "old boot bind failed", since: "2026-10-31T12:00:00Z", attempt: 7, maxAttempts: 8 }],
  }));
  await openProtection(page);
  const notice = page.getByRole("status", { name: "Dataplane protection" });
  await expect(notice).toContainText("old boot bind failed");
  mock.status = observation({ bootId: "boot-b", applyId: "apply-b", state: "pending", components: [] });
  await page.clock.runFor(2_000);
  await expect(notice).not.toContainText("old boot bind failed");
  await expect(notice).not.toContainText("retry 7/8");
  mock.readStatus = 503;
  mock.status = { error: "no engine" };
  await page.clock.runFor(2_000);
  await expect(notice).toContainText("Protection unknown");
  await expect(notice).not.toContainText("nfqueue:101");
});

test("pending polls at two seconds; commit accelerates otherwise slow polling for ten seconds", async ({ page }) => {
  await page.clock.install();
  const mock = await protectionAPI(page, observation({ state: "pending" }));
  await openProtection(page, "/ics/");
  await page.clock.pauseAt(Date.now() + 1_000);
  const tick = async (ms: number, expected: number) => {
    await page.clock.runFor(ms);
    await expect.poll(() => mock.reads).toBe(expected);
    // Let the response settle and schedule the next timeout on the paused clock.
    await expect(page.getByRole("status", { name: "Dataplane protection" })).toHaveCount(mock.status && (mock.status as { state: string }).state === "protecting" ? 0 : 1);
  };
  const base = mock.reads;
  await tick(2_000, base + 1);
  mock.status = observation();
  await tick(2_000, base + 2);
  await page.clock.runFor(10_000);
  expect(mock.reads).toBe(base + 2);
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:staged")));
  expect(mock.reads).toBe(base + 2);
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:committed")));
  await expect.poll(() => mock.reads).toBe(base + 3);
  await expect(page.getByRole("status", { name: "Dataplane protection" })).toHaveCount(0);
  for (let i = 1; i <= 5; i++) await tick(2_000, base + 3 + i);
  await page.clock.runFor(29_000);
  expect(mock.reads).toBe(base + 8);
  await tick(1_000, base + 9);
});

test("malformed observations are never verified protecting", () => {
  expect(isProtectionStatus(observation())).toBe(true);
  for (const value of [null, {}, { ...observation(), effects: null }, { ...observation(), components: [{}] },
    { ...observation(), state: "new-state" }, { ...observation(), retryable: "yes" }]) {
    expect(isProtectionStatus(value)).toBe(false);
  }
});
