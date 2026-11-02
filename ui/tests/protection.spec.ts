import { expect, test } from "@playwright/test";
import { isProtectionStatus } from "../lib/api-protection";
import { observation, openProtection, protectionAPI, subsystem } from "./fixtures/protection-api";

declare global { interface Window { configCommits: number } }

test("an engine awaiting its first configuration does not imply a commit", async ({ page }) => {
  await protectionAPI(page, observation({
    state: "pending", applyId: "", installedApplyId: "",
    components: [{ name: "nft", required: true, state: "pending", reason: "awaiting configuration",
      since: "2026-10-31T12:00:00Z" }],
    effects: [],
  }));
  await openProtection(page);
  const notice = page.getByRole("status", { name: "Traffic protection" });
  await expect(notice.locator("p").first()).toHaveText("Waiting for configuration");
  await expect(notice).not.toContainText("Committed");
  await expect(notice).toContainText("awaiting configuration");
  await expect(notice.getByText("nft: awaiting configuration", { exact: true })).toBeVisible();
  await expect(notice.getByText(/Boot ID:/)).not.toBeVisible();
  await notice.getByRole("button", { name: "Technical details", exact: true }).click();
  await expect(notice.getByText(/Boot ID:/)).toBeVisible();
  await expect(notice.getByText("nft: awaiting configuration", { exact: true })).toBeVisible();
  await expect(notice).toContainText("Wait for protection to finish, then check status.");
  await expect(notice.getByRole("button", { name: "Retry now", exact: true })).toHaveCount(0);
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
    const notice = page.getByRole("status", { name: "Traffic protection" });
    await expect(notice).toContainText("Committed — protection pending");
    await expect(notice).toContainText("IEC 104 commands is dropping (fail closed)");
    if (bounded) await expect(notice).toContainText("retry 2/8");
    else await expect(notice).not.toContainText("retry ");
    await expect(notice.getByRole("button", { name: "Retry now", exact: true })).toHaveCount(0);
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
  const notice = page.getByRole("status", { name: "Traffic protection" });
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
  const notice = page.getByRole("status", { name: "Traffic protection" });
  await expect(notice).toContainText("Configured but not protecting — IEC 104 commands is dropping (fail closed)");
  await expect(notice).toContainText("Monitor traffic is not being inspected by containd");
  await expect(notice).not.toContainText("Monitor traffic is dropping");
});

test("monitor-only failure never claims a drop", async ({ page }) => {
  await protectionAPI(page, observation({
    state: "failed", effects: [{ traffic: "Monitor IEC 104", effect: "not_inspected" }],
  }));
  await openProtection(page);
  const notice = page.getByRole("status", { name: "Traffic protection" });
  await expect(notice).toContainText("Inspection unavailable — Monitor IEC 104 is not being inspected by containd");
  await expect(notice).not.toContainText("drop");
});

test("degraded logging names the missing evidence and offers admin retry", async ({ page }) => {
  await protectionAPI(page, observation({ state: "degraded", retryable: true }), { enforcement: "degraded" });
  await openProtection(page);
  const notice = page.getByRole("status", { name: "Traffic protection" });
  await expect(notice).toContainText("Rule-hit logging unavailable");
  await expect(notice).toContainText("Firewall rules are active");
  await expect(notice.getByText("Not verified", { exact: true })).toHaveCount(1);
  await expect(notice.getByRole("button", { name: "Retry now" })).toBeVisible();
});

test("viewers cannot retry a retryable failure", async ({ page }) => {
  const mock = await protectionAPI(page, observation({ state: "failed", retryable: true }), { role: "view" });
  await openProtection(page, "/firewall/");
  await expect(page.getByRole("status", { name: "Traffic protection" })).toContainText("Configured but not protecting");
  await expect(page.getByRole("button", { name: "Retry now" })).toHaveCount(0);
  expect(mock.retries).toEqual([]);
});

test("admin retries the exact boot/apply observation, then polls without optimistic green", async ({ page }) => {
  const failed = observation({ state: "failed", retryable: true });
  const mock = await protectionAPI(page, failed);
  mock.afterRetry = observation({ state: "pending" });
  await openProtection(page);
  const notice = page.getByRole("status", { name: "Traffic protection" });
  await notice.getByRole("button", { name: "Retry now" }).click();
  await expect(notice).toContainText("Committed — protection pending");
  expect(mock.retries).toEqual([{ bootId: failed.bootId, applyId: failed.applyId, desiredRevision: failed.desiredRevision }]);
  expect(mock.reads).toBeGreaterThan(1);
});

test("retry accelerates a degraded observation for ten seconds without retrying automatically", async ({ page }) => {
  await page.clock.install();
  const mock = await protectionAPI(page, observation({ state: "degraded", retryable: true }));
  await openProtection(page);
  await page.clock.pauseAt(Date.now() + 1_000);
  const notice = page.getByRole("status", { name: "Traffic protection" });
  await notice.getByRole("button", { name: "Technical details", exact: true }).click();
  const observedAt = notice.locator("time").first();
  await expect(observedAt).toHaveAttribute("datetime", "2026-10-31T12:00:00Z");
  const before = mock.reads;
  const retryObservedAt = "2026-10-31T12:00:01Z";
  mock.status = observation({ state: "degraded", retryable: true, observedAt: retryObservedAt });
  await notice.getByRole("button", { name: "Retry now" }).click();
  await expect.poll(() => mock.reads).toBe(before + 1);
  await expect(notice).toContainText("Retry requested; checking protection.");
  await expect(observedAt).toHaveAttribute("datetime", retryObservedAt);
  for (let i = 1; i <= 5; i++) {
    const nextObservedAt = `2026-10-31T12:00:0${i + 1}Z`;
    mock.status = observation({ state: "degraded", retryable: true, observedAt: nextObservedAt });
    await page.clock.runFor(2_000);
    await expect.poll(() => mock.reads).toBe(before + 1 + i);
    await expect(observedAt).toHaveAttribute("datetime", nextObservedAt);
  }
  await page.clock.runFor(29_000);
  expect(mock.reads).toBe(before + 6);
  const finalObservedAt = "2026-10-31T12:00:07Z";
  mock.status = observation({ state: "degraded", retryable: true, observedAt: finalObservedAt });
  await page.clock.runFor(1_000);
  await expect.poll(() => mock.reads).toBe(before + 7);
  await expect(observedAt).toHaveAttribute("datetime", finalObservedAt);
  expect(mock.retries).toHaveLength(1);
});

test("a failed retry reports the error and refreshes, without claiming recovery", async ({ page }) => {
  const mock = await protectionAPI(page, observation({ state: "failed", retryable: true }));
  mock.retryStatus = 502;
  await openProtection(page);
  const notice = page.getByRole("status", { name: "Traffic protection" });
  await notice.getByRole("button", { name: "Retry now" }).click();
  await expect(notice).toContainText("Retry failed: protection retry refused");
  await expect(notice).toContainText("Configured but not protecting");
  expect(mock.retries).toHaveLength(1);
  expect(mock.reads).toBeGreaterThan(1);
});

for (const code of ["protection_superseded"]) {
  test(`retry ${code} refreshes without replaying the request`, async ({ page }) => {
    const mock = await protectionAPI(page, observation({ state: "failed", retryable: true }));
    mock.retryStatus = 409;
    mock.retryCode = code;
    mock.afterRetry = observation({ state: "failed", retryable: false });
    await openProtection(page);
    const notice = page.getByRole("status", { name: "Traffic protection" });
    await notice.getByRole("button", { name: "Retry now" }).click();
    await expect(notice).toContainText("Protection changed.");
    await expect(notice.getByRole("button", { name: "Retry now", exact: true })).toHaveCount(0);
    expect(mock.retries).toHaveLength(1);
    expect(mock.reads).toBeGreaterThan(1);
  });
}

test("read failure replaces protecting with unknown and removes all stale detail", async ({ page }) => {
  await page.clock.install();
  const mock = await protectionAPI(page, observation(), { enforcement: "enforcing" });
  await openProtection(page);
  await expect(page.getByRole("status", { name: "Traffic protection" })).toHaveCount(0);
  mock.readStatus = 502;
  mock.status = { error: "engine unreachable" };
  await page.clock.runFor(30_000);
  const notice = page.getByRole("status", { name: "Traffic protection" });
  await expect(notice).toContainText("Protection unknown");
  await expect(notice.getByText("Protecting", { exact: true })).toHaveCount(0);
  await expect(notice.getByRole("button", { name: "Retry now", exact: true })).toHaveCount(0);
});

test("a new boot/apply replaces component detail rather than merging it", async ({ page }) => {
  await page.clock.install();
  const mock = await protectionAPI(page, observation({
    state: "pending", components: [{ name: "nfqueue:101", state: "pending", required: true,
      reason: "old boot bind failed", since: "2026-10-31T12:00:00Z", attempt: 7, maxAttempts: 8 }],
  }));
  await openProtection(page);
  const notice = page.getByRole("status", { name: "Traffic protection" });
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
  const notice = page.getByRole("status", { name: "Traffic protection" });
  await notice.getByRole("button", { name: "Technical details", exact: true }).click();
  const observedAt = notice.locator("time").first();
  await expect(observedAt).toHaveAttribute("datetime", "2026-10-31T12:00:00Z");
  const setObservation = (state: "pending" | "protecting" | "degraded", sequence: number) => {
    const nextObservedAt = `2026-10-31T12:00:0${sequence}Z`;
    mock.status = observation({ state, retryable: state === "degraded", observedAt: nextObservedAt });
    return nextObservedAt;
  };
  const tick = async (ms: number, expected: number) => {
    await page.clock.runFor(ms);
    await expect.poll(() => mock.reads).toBe(expected);
    await expect(page.getByRole("status", { name: "Traffic protection" })).toHaveCount(mock.status && (mock.status as { state: string }).state === "protecting" ? 0 : 1);
  };
  const base = mock.reads;
  const firstObservedAt = setObservation("pending", 1);
  await tick(2_000, base + 1);
  await expect(observedAt).toHaveAttribute("datetime", firstObservedAt);
  setObservation("protecting", 2);
  await tick(2_000, base + 2);
  await page.clock.runFor(10_000);
  expect(mock.reads).toBe(base + 2);
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:staged")));
  expect(mock.reads).toBe(base + 2);
  const committedObservedAt = setObservation("degraded", 3);
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:committed")));
  await expect.poll(() => mock.reads).toBe(base + 3);
  await expect(observedAt).toHaveAttribute("datetime", committedObservedAt);
  for (let i = 1; i <= 5; i++) {
    const nextObservedAt = setObservation("degraded", i + 3);
    await tick(2_000, base + 3 + i);
    await expect(observedAt).toHaveAttribute("datetime", nextObservedAt);
  }
  await page.clock.runFor(29_000);
  expect(mock.reads).toBe(base + 8);
  const finalObservedAt = setObservation("degraded", 9);
  await tick(1_000, base + 9);
  await expect(observedAt).toHaveAttribute("datetime", finalObservedAt);
});

test("malformed observations are never verified protecting", () => {
  expect(isProtectionStatus(observation())).toBe(true);
  for (const value of [null, {}, { ...observation(), effects: null }, { ...observation(), components: [{}] },
    { ...observation(), state: "new-state" }, { ...observation(), retryable: "yes" }]) {
    expect(isProtectionStatus(value)).toBe(false);
  }
});

test("ready hides the traffic banner and shows the three revision identities", async ({ page }) => {
  await protectionAPI(page, observation(), { enforcement: "enforcing" });
  await openProtection(page, "/config/");
  await expect(page.getByRole("status", { name: "Traffic protection" })).toHaveCount(0);
  const summary = page.getByRole("region", { name: "Running protection summary" });
  await expect(summary.getByText("Desired configuration", { exact: true })).toBeVisible();
  await expect(summary.getByText("Policy installed", { exact: true })).toBeVisible();
  await expect(summary.getByText("Protecting now", { exact: true })).toBeVisible();
  await expect(summary.getByText("running-a", { exact: true })).toHaveCount(3);
});

test("a pending required owner prevents green even when health says enforcing", async ({ page }) => {
  await protectionAPI(page, observation({ state: "pending", subsystems: [subsystem()] }), { enforcement: "enforcing" });
  await openProtection(page, "/firewall/");
  const notice = page.getByRole("status", { name: "Traffic protection" });
  await expect(notice).toContainText("Configuration committed; interfaces are retrying");
  await expect(notice).toContainText("Required");
  await expect(notice).toContainText("Next automatic retry");
  await expect(notice).toContainText("Automatic repair is underway");
  await expect(notice.getByText("Not verified", { exact: true })).toBeVisible();
  await expect(page.getByRole("status", { name: "Firewall enforcing: healthy", exact: true })).toHaveCount(0);
  const dir = process.env.PROTECTION_SCREENSHOTS_DIR;
  if (dir) {
    for (const viewport of [{ width: 1280, height: 800 }, { width: 390, height: 844 }]) {
      await page.setViewportSize(viewport);
      await expect(notice).toBeVisible();
      await page.screenshot({ path: `${dir}/protection-${viewport.width}.png`, animations: "disabled" });
    }
  }
});

test("DHCP faults remain visible and retryable without gating ready", async ({ page }) => {
  const mock = await protectionAPI(page, observation({ subsystems: [subsystem({
    name: "dhcp", owner: "management", required: false, state: "failed",
    fault: { kind: "delivery", reason: "DHCP could not start; retrying" },
  })] }), { enforcement: "enforcing" });
  await openProtection(page, "/config/");
  await expect(page.getByRole("status", { name: "Traffic protection" })).toHaveCount(0);
  const services = page.getByRole("status", { name: "Service convergence" });
  await expect(services).toContainText("DHCP could not start; retrying");
  await expect(services).toContainText("Non-gating");
  await expect(services).toContainText("Next automatic retry");
  await services.getByRole("button", { name: "Retry now" }).click();
  expect(mock.retries).toEqual([{ bootId: "boot-a", applyId: "apply-a", desiredRevision: "running-a" }]);
  const summary = page.getByRole("region", { name: "Running protection summary" });
  await expect(summary.getByText("running-a", { exact: true })).toHaveCount(3);
  const dir = process.env.PROTECTION_SCREENSHOTS_DIR;
  if (dir) {
    for (const viewport of [{ width: 1280, height: 800 }, { width: 390, height: 844 }]) {
      await page.setViewportSize(viewport);
      await summary.evaluate(el => el.parentElement!.scrollIntoView({ block: "start" }));
      await page.screenshot({ path: `${dir}/config-summary-${viewport.width}.png`, animations: "disabled" });
    }
  }
});

test("a new boot clears a previously healthy claim without retaining installation detail", async ({ page }) => {
  await page.clock.install();
  const mock = await protectionAPI(page, observation(), { enforcement: "enforcing" });
  await openProtection(page, "/topology/");
  const chip = page.getByRole("status", { name: "Firewall enforcement", exact: true });
  await expect(chip).toContainText("ENFORCING");
  mock.status = observation({ bootId: "boot-b", applyId: "", installedApplyId: "", runningRevision: "", mode: "",
    state: "unknown", ready: false, installed: null, appliedRevision: null, protectingRevision: null, components: [], effects: [] });
  await page.clock.runFor(30_000);
  await expect(chip).toContainText("STATUS UNKNOWN");
  const notice = page.getByRole("status", { name: "Traffic protection" });
  await expect(notice.getByText("Not verified", { exact: true })).toHaveCount(2);
  await expect(notice).not.toContainText("boot-a");
});


test("collection failure preserves visible non-gating faults without clean readiness", async ({ page }) => {
  const mock = await protectionAPI(page, observation({ state: "unknown", subsystems: [subsystem({
    name: "dns", required: false, state: "failed", fault: { kind: "config", reason: "DNS upstream missing" },
    retryable: false, nextRetryAt: null,
  })] }));
  mock.readStatus = 502;
  await openProtection(page);
  await expect(page.getByRole("status", { name: "Traffic protection" })).toContainText("Protection unknown");
  const services = page.getByRole("status", { name: "Service convergence" });
  await expect(services).toContainText("DNS upstream missing");
  await expect(services).toContainText("Review the service configuration");
});

test("superseded retry refreshes a different target and retires obsolete feedback", async ({ page }) => {
  const mock = await protectionAPI(page, observation({ state: "failed", retryable: true }));
  mock.retryStatus = 409;
  mock.retryCode = "protection_superseded";
  mock.afterRetry = observation({ state: "pending", applyId: "apply-b", desiredRevision: "running-b", subsystems: [subsystem({ desiredRevision: "running-b" })] });
  await openProtection(page);
  const notice = page.getByRole("status", { name: "Traffic protection" });
  await notice.getByRole("button", { name: "Retry now" }).click();
  await expect(notice).toContainText("running-b");
  await expect(notice).not.toContainText("Protection changed.");
  expect(mock.retries).toHaveLength(1);
  expect(mock.reads).toBeGreaterThan(1);
});


test("unlabelled retry acceptance is rejected rather than normalized", async ({ page }) => {
  const mock = await protectionAPI(page, observation({ state: "failed", retryable: true }));
  mock.retryResponse = { status: "retrying", applyId: "apply-a" };
  await openProtection(page);
  const notice = page.getByRole("status", { name: "Traffic protection" });
  await notice.getByRole("button", { name: "Retry now" }).click();
  await expect(notice).toContainText("Retry acceptance could not be verified");
  expect(mock.retries).toHaveLength(1);
});


test("disabled enforcement does not hide a required service teardown failure", async ({ page }) => {
  await protectionAPI(page, observation({ state: "disabled", subsystems: [subsystem({ name: "wireguard", operation: "stop",
    state: "failed", fault: { kind: "delivery", reason: "WireGuard teardown unverified" } })] }));
  await openProtection(page);
  const notice = page.getByRole("status", { name: "Traffic protection" });
  await expect(notice).toContainText("Protection disabled");
  await expect(notice).toContainText("WireGuard teardown unverified");
});


test("trust storage invalidates live readiness without a fake configuration commit", async ({ page }) => {
  const mock = await protectionAPI(page, observation(), { enforcement: "enforcing" });
  await page.route("**/api/v1/system/tls/trusted-ca", async route => {
    route.request().postDataJSON();
    mock.status = observation({ state: "pending", subsystems: [subsystem({ name: "trust", desiredTrustRevision: "sha256:new" })] });
    await route.fulfill({ json: { status: "stored", revision: "sha256:new", warnings: ["trust: owner acknowledgement pending"] } });
  });
  await openProtection(page, "/system/settings/");
  const reads = mock.reads;
  await page.evaluate(() => {
    window.configCommits = 0;
    window.addEventListener("containd:config:committed", () => { window.configCommits++; });
  });
  const card = page.locator("section").filter({ hasText: "Trusted CAs (outbound)" });
  await card.locator('input[type="file"]').setInputFiles({ name: "ca.pem", mimeType: "application/x-pem-file", buffer: Buffer.from("certificate") });
  await card.getByRole("button", { name: "Upload CA bundle" }).click();
  await expect(page.getByRole("status", { name: "Traffic protection" })).toContainText("trust is retrying");
  expect(mock.reads).toBeGreaterThan(reads);
  expect(await page.evaluate(() => window.configCommits)).toBe(0);
});
