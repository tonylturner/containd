import { expect, test } from "@playwright/test";

import { normalizeFirewallRule } from "../lib/api-normalize";
import { parseIdentityLabels, validateIdentityLabel } from "../lib/validate";
import {
  buildPolicy,
  formatSchedule,
  policyDraftFrom,
  tagsInUse,
  type PolicyDraft,
} from "../app/firewall/firewall-rule-policy";

// Pure model tests: no page, no server. The bounds mirror the server's rule
// validation, which stays authoritative.

function draft(patch: Partial<PolicyDraft>): PolicyDraft {
  return { ...policyDraftFrom(), ...patch };
}

function error(d: PolicyDraft, inUse: string[] = []): string {
  const built = buildPolicy(d, inUse);
  return built.ok ? "" : built.error;
}

test("rate limits accept exactly the server's bounds", () => {
  const rl = (pps: string, burst = "") => buildPolicy(draft({ action: "RATE_LIMIT", pps, burst }), []);
  expect(rl("1")).toEqual({ ok: true, value: { action: "RATE_LIMIT", identities: [], rateLimit: { packetsPerSecond: 1 } } });
  expect(rl("1000000", "1000000")).toMatchObject({ ok: true, value: { rateLimit: { packetsPerSecond: 1000000, burst: 1000000 } } });
  // Burst 0 means packetsPerSecond, so it is not sent.
  expect(rl("50", "0")).toMatchObject({ ok: true, value: { rateLimit: { packetsPerSecond: 50 } } });
  for (const bad of ["0", "1000001", "1.5", "-3", "", "1e3"]) expect(rl(bad).ok).toBe(false);
  expect(rl("10", "1000001").ok).toBe(false);
  // Fields of other actions are not staged.
  expect(buildPolicy(draft({ action: "DENY", pps: "5", tag: "x" }), [])).toEqual({ ok: true, value: { action: "DENY", identities: [] } });
});

test("tags follow the label pattern and the per-config limit", () => {
  for (const tag of ["a", "eng-access", "ot.zone_2", "0" + "a".repeat(31)]) {
    expect(buildPolicy(draft({ action: "TAG", tag }), [])).toMatchObject({ ok: true, value: { tag } });
  }
  for (const tag of ["", "-lead", "Upper", "has space", "a".repeat(33)]) {
    expect(error(draft({ action: "TAG", tag }))).toContain("Tag: use 1-32 characters");
  }
  const full = Array.from({ length: 32 }, (_, i) => `t${i}`);
  expect(error(draft({ action: "TAG", tag: "new" }), full)).toContain("at most 32 distinct tag labels");
  expect(buildPolicy(draft({ action: "TAG", tag: "t5" }), full).ok).toBe(true);
  expect(error(draft({ action: "TAG", tag: "ok", scheduled: true, days: ["Monday"] }))).toContain("takes no schedule");
});

test("schedules mirror the server's calendar rules", () => {
  const sched = (patch: Partial<PolicyDraft>) => buildPolicy(draft({ scheduled: true, ...patch }), []);
  expect(sched({ days: ["Saturday", "Monday"], start: "22:00", end: "02:00", timezone: "America/New_York" })).toMatchObject({
    ok: true,
    value: { schedule: { daysOfWeek: ["Monday", "Saturday"], startTime: "22:00", endTime: "02:00", timezone: "America/New_York" } },
  });
  expect(sched({ start: "09:00" })).toMatchObject({ ok: true, value: { schedule: { startTime: "09:00" } } });
  expect(error(draft({ scheduled: true, start: "09:00", end: "09:00" }))).toContain("must differ");
  // A blank start is 00:00.
  expect(error(draft({ scheduled: true, end: "00:00" }))).toContain("must differ");
  expect(error(draft({ scheduled: true, start: "24:00" }))).toContain("24-hour HH:MM");
  expect(error(draft({ scheduled: true, days: ["Monday"], timezone: "Not/AZone" }))).toContain("not an IANA timezone");
  expect(error(draft({ scheduled: true }))).toContain("choose days or a time window");
  expect(buildPolicy(draft({ scheduled: false, start: "x" }), [])).toMatchObject({ ok: true, value: { action: "ALLOW" } });
});

test("identity labels are 1-64 printable bytes, distinct, without surrounding spaces", () => {
  expect(parseIdentityLabels(" operator , eng lead ,")).toEqual({ ok: true, labels: ["operator", "eng lead"] });
  expect(parseIdentityLabels("a, a")).toEqual({ ok: false, error: 'identity "a" is listed twice' });
  expect(validateIdentityLabel("é".repeat(32))).toBeNull();
  expect(validateIdentityLabel("é".repeat(33))).toContain("1 to 64 bytes");
  expect(validateIdentityLabel(" x")).toContain("surrounding spaces");
  expect(validateIdentityLabel("tab\there")).toContain("non-printable");
  expect(validateIdentityLabel("nb sp")).toContain("non-printable");
  expect(error(draft({ identities: "ok, " + "x".repeat(65) }))).toContain("Identities:");
});

test("drafts round-trip a stored rule", () => {
  const rule = normalizeFirewallRule({
    id: "r", action: "RATE_LIMIT", rateLimit: { packetsPerSecond: 10, burst: 4 }, identities: ["ops"],
    schedule: { daysOfWeek: ["Friday", "Monday"], startTime: "08:00", timezone: "UTC" },
  });
  const d = policyDraftFrom(rule);
  expect(d).toMatchObject({ action: "RATE_LIMIT", pps: "10", burst: "4", identities: "ops", scheduled: true, days: ["Monday", "Friday"] });
  expect(buildPolicy(d, [])).toEqual({
    ok: true,
    value: {
      action: "RATE_LIMIT", identities: ["ops"], rateLimit: { packetsPerSecond: 10, burst: 4 },
      schedule: { daysOfWeek: ["Monday", "Friday"], startTime: "08:00", timezone: "UTC" },
    },
  });
});

test("the normalizer keeps every action and its parameters", () => {
  expect(normalizeFirewallRule({ id: "a", action: "RESET" }).action).toBe("RESET");
  expect(normalizeFirewallRule({ id: "b", action: "TAG", tag: "eng" })).toMatchObject({ action: "TAG", tag: "eng" });
  expect(normalizeFirewallRule({ id: "c", action: "RATE_LIMIT", rateLimit: { packetsPerSecond: 5 } }).rateLimit).toEqual({ packetsPerSecond: 5 });
  expect(normalizeFirewallRule({ id: "d", action: "RATE_LIMIT", rateLimit: { packetsPerSecond: "5" } }).rateLimit).toBeUndefined();
  expect(normalizeFirewallRule({ id: "e", action: "LOG" }).action).toBe("DENY");
});

test("tag usage and schedule summaries", () => {
  const rules = [
    { id: "a", action: "TAG" as const, tag: "x" },
    { id: "b", action: "TAG" as const, tag: "x" },
    { id: "c", action: "TAG" as const, tag: "y" },
  ];
  expect(tagsInUse(rules)).toEqual(["x", "y"]);
  expect(tagsInUse(rules, "c")).toEqual(["x"]);
  expect(formatSchedule({ endTime: "06:00" })).toBe("daily 00:00-06:00 UTC");
  expect(formatSchedule({ daysOfWeek: ["Sunday"], timezone: "Asia/Tokyo" })).toBe("Sun Asia/Tokyo");
});
