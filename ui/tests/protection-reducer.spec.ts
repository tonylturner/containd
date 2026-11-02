import { expect, test } from "@playwright/test";
import { isProtectionStatus, isProtectionSubsystem } from "../lib/api-protection";
import { isRuntimeApplyResult, isFactoryResetResult } from "../lib/api-runtime-result";
import { canRetryProtection, protectionOutstanding, reduceProtection, sameProtectionTarget } from "../lib/protection-store";
import { observation, subsystem, runtimeResult } from "./fixtures/protection-api";

test("only the newest request may replace the whole observation", () => {
  const current = { status: observation({ bootId: "boot-b" }), retrying: false };
  expect(reduceProtection(current, observation(), 1, 2)).toBe(current);
  const next = observation({ state: "unknown", bootId: "boot-c", components: [], subsystems: [] });
  expect(reduceProtection(current, next, 2, 2).status).toBe(next);
});

test("retry feedback retires on boot, apply, desired or trust changes, never timestamp order", () => {
  const status = observation({ subsystems: [subsystem({ name: "trust", desiredTrustRevision: "trust-a" })] });
  const current = { status, retrying: false, retryMessage: "old feedback" };
  for (const update of [{ bootId: "boot-b" }, { applyId: "apply-b" }, { desiredRevision: "running-b" },
    { subsystems: [subsystem({ name: "trust", desiredTrustRevision: "trust-b" })] }]) {
    expect(sameProtectionTarget(status, { ...status, ...update })).toBe(false);
    expect(reduceProtection(current, { ...status, ...update }, 2, 2).retryMessage).toBeUndefined();
  }
  expect(reduceProtection(current, { ...status, observedAt: "earlier" }, 2, 2).retryMessage).toBe("old feedback");
});

test("service retries do not depend on raw engine retryable and poll quickly", () => {
  const status = observation({ subsystems: [subsystem({ name: "dhcp", required: false })] });
  expect(status.retryable).toBe(false);
  expect(canRetryProtection(status)).toBe(true);
  expect(protectionOutstanding(status)).toBe(true);
  expect(canRetryProtection({ ...status, desiredRevision: null })).toBe(false);
  expect(canRetryProtection({ ...status, bootId: "" })).toBe(false);
});

test("only required pending work or an active retry keeps protection polling fast", () => {
  const optionalPending = observation({ subsystems: [subsystem({
    name: "scanner", required: false, state: "pending", reason: "disabled", retryable: false, nextRetryAt: null,
  })] });
  expect(protectionOutstanding(optionalPending)).toBe(false);
  expect(protectionOutstanding({ ...optionalPending, subsystems: [subsystem({
    name: "scanner", required: false, state: "pending", reason: "scanner starting", retryable: false, nextRetryAt: null,
  })] })).toBe(false);
  expect(protectionOutstanding({ ...optionalPending, components: [{
    name: "nft", required: true, state: "pending", reason: "install pending", since: "",
  }] })).toBe(true);
  expect(protectionOutstanding({ ...optionalPending, subsystems: [subsystem({
    name: "dhcp", required: false, state: "ready", retryable: false, nextRetryAt: "2026-11-02T12:00:00Z",
  })] })).toBe(true);
  expect(protectionOutstanding({ ...optionalPending, subsystems: [subsystem({
    name: "scanner", required: false, state: "off", retryable: true, nextRetryAt: "2026-11-02T12:00:00Z",
  })] })).toBe(false);
});

test("validators reject legacy aggregates, malformed owner proofs and transition responses", () => {
  const status = observation();
  expect(isProtectionStatus(status)).toBe(true);
  for (const field of ["ready", "runningRevision", "desiredRevision", "appliedRevision", "protectingRevision", "installed", "mode", "subsystems"] as const) {
    const legacy: Record<string, unknown> = { ...status };
    delete legacy[field];
    expect(isProtectionStatus(legacy), field).toBe(false);
  }
  for (const update of [{ desiredRevision: null }, { protectingRevision: `${status.protectingRevision}-other` }, { mode: "recovery" }, { bootId: "" }, { installed: null },
    { installed: { ...status.installed!, applyId: `${status.applyId}-other` } },
    { desiredRevision: "not a token" }]) {
    expect(isProtectionStatus({ ...status, ...update })).toBe(false);
  }
  expect(isProtectionSubsystem(subsystem())).toBe(true);
  for (const update of [{ acknowledged: {} }, { fault: { kind: "new", reason: "fault" } }, { nextRetryAt: false }, { attempt: -1 }]) {
    expect(isProtectionSubsystem({ ...subsystem(), ...update })).toBe(false);
  }
  expect(isRuntimeApplyResult(runtimeResult())).toBe(true);
  expect(isRuntimeApplyResult({ status: "committed" })).toBe(false);
  expect(isFactoryResetResult({ ...runtimeResult("reset"), loggedOut: true, message: "reset", warnings: [] })).toBe(true);
  expect(isFactoryResetResult({ ...runtimeResult("reset"), loggedOut: true, message: "reset" })).toBe(false);
});
