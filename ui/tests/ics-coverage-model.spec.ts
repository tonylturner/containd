import { expect, test } from "@playwright/test";

import {
  normalizeICSCoverageList,
  normalizeICSCoverageRule,
  normalizeICSEnforcementHealth,
  sameICSCoverage,
} from "../lib/api-ics-coverage";
import {
  coverageViewFromPreview,
  describeRuleCoverage,
  formatReason,
  icsEnforcementIndicator,
  type ICSCoverageView,
} from "../app/ics/ics-coverage-model";
import { formatICSMode } from "../app/ics/ics-shared";

// Pure model tests: no page, no server.

const enforcing = { ruleId: "r1", protocol: "modbus", mode: "enforce", state: "enforcing" as const, reasons: [] };
const exclusion = { code: "exclusion-overlap", message: "exclusion 10.0.0.0/24 meets the rule scope", value: "10.0.0.0/24" };

function loaded(candidate: unknown[], applied: unknown[] | null): ICSCoverageView {
  return coverageViewFromPreview({
    runtime: { iec104EnvelopeOpen: false, reason: "" },
    icsCoverage: normalizeICSCoverageList(candidate),
    engineStatus: applied ? { icsCoverage: normalizeICSCoverageList(applied) } : undefined,
    engineStatusError: applied ? undefined : "engine unreachable",
  });
}

test("partial and malformed coverage normalises without inventing protection", () => {
  expect(normalizeICSCoverageList(undefined)).toEqual([]);
  expect(normalizeICSCoverageList({ ruleId: "r1" })).toEqual([]);
  expect(normalizeICSCoverageList([null, 3, { state: "enforcing" }, { ruleId: "r2" }])).toEqual([
    { ruleId: "r2", protocol: "", mode: "", state: "unknown", reasons: [] },
  ]);
  expect(
    normalizeICSCoverageRule({
      ruleId: "r3",
      protocol: "dnp3",
      mode: "ENFORCE",
      state: "protected",
      reasons: [{ code: "dpi-disabled" }, {}, "x", { ...exclusion, matches: -1 }],
    }),
  ).toEqual({
    ruleId: "r3",
    protocol: "dnp3",
    mode: "enforce",
    state: "unknown",
    reasons: [{ code: "dpi-disabled", message: "dpi-disabled" }, exclusion],
  });
  expect(normalizeICSEnforcementHealth(undefined)).toBeUndefined();
  expect(normalizeICSEnforcementHealth({ state: "great", enforcing: "2" })).toEqual({
    state: "unknown",
    enforcing: 0,
    partial: 0,
    notEnforcing: 0,
    monitoring: 0,
  });
});

test("runtime match counts do not make the candidate differ from the applied rule", () => {
  const candidate = { ...enforcing, state: "partial" as const, reasons: [exclusion] };
  const applied = { ...candidate, reasons: [{ ...exclusion, matches: 4 }] };
  expect(sameICSCoverage(candidate, applied)).toBe(true);
  expect(sameICSCoverage(candidate, { ...candidate, reasons: [{ ...exclusion, value: "10.1.0.0/24" }] })).toBe(false);
  expect(sameICSCoverage(candidate, { ...candidate, mode: "learn" })).toBe(false);
});

test("each coverage state maps to its badge and never to green unless enforcing", () => {
  const states = ["enforcing", "partial", "not_enforcing", "monitoring", "bogus"];
  const view = loaded([], states.map((state) => ({ ...enforcing, ruleId: state, state })));
  expect(states.map((s) => describeRuleCoverage(view, s)[0])).toEqual([
    { label: "applied: enforcing", variant: "success", reasons: [] },
    { label: "applied: partial", variant: "warning", reasons: [] },
    { label: "applied: not enforcing", variant: "error", reasons: [] },
    { label: "applied: monitoring", variant: "neutral", reasons: [] },
    { label: "applied: unknown", variant: "neutral", reasons: [] },
  ]);
});

test("candidate coverage is shown only where it differs from the applied rule", () => {
  const same = loaded([enforcing], [enforcing]);
  expect(describeRuleCoverage(same, "r1").map((l) => l.label)).toEqual(["applied: enforcing"]);

  const queue = { code: "queue-unavailable", message: "queue 101 is not bound by this engine" };
  const differs = loaded([enforcing], [{ ...enforcing, state: "not_enforcing", reasons: [queue] }]);
  expect(describeRuleCoverage(differs, "r1")).toEqual([
    { label: "applied: not enforcing", variant: "error", reasons: [queue] },
    { label: "candidate: enforcing", variant: "success", reasons: [] },
  ]);

  const pending = loaded([enforcing], []);
  expect(describeRuleCoverage(pending, "r1").map((l) => l.label)).toEqual(["not applied", "candidate: enforcing"]);

  const engineDown = loaded([enforcing], null);
  expect(engineDown.status === "loaded" && engineDown.appliedError).toBe("engine unreachable");
  expect(describeRuleCoverage(engineDown, "r1").map((l) => l.label)).toEqual(["applied: unknown", "candidate: enforcing"]);
});

test("coverage without data never reads as enforcement", () => {
  for (const view of [
    { status: "loading" },
    { status: "restricted" },
    { status: "unavailable", error: "x" },
  ] as ICSCoverageView[]) {
    const lines = describeRuleCoverage(view, "r1");
    expect(lines).toHaveLength(1);
    expect(lines[0].variant).toBe("neutral");
  }
});

test("reasons name the exclusion and its runtime matches", () => {
  expect(formatReason({ code: "dpi-disabled", message: "DPI is switched off" })).toBe("DPI is switched off");
  expect(formatReason({ code: "domain-exclusion", message: "a domain exclusion can bypass inspection", value: "plc.example", matches: 1 }))
    .toBe("a domain exclusion can bypass inspection (plc.example) — 1 flow bypassed inspection since apply");
  expect(formatReason({ ...exclusion, matches: 3 }))
    .toBe("exclusion 10.0.0.0/24 meets the rule scope — 3 flows bypassed inspection since apply");
});

test("the health aggregate maps each state to its indicator", () => {
  const counts = { enforcing: 2, partial: 1, notEnforcing: 0, monitoring: 3 };
  expect(icsEnforcementIndicator(undefined)).toEqual({ status: "unknown", label: "ICS protocol enforcement", sublabel: "status unavailable" });
  expect(icsEnforcementIndicator({ state: "partial", ...counts })).toEqual({
    status: "degraded",
    label: "ICS protocol rules partially enforcing",
    sublabel: "2 enforcing, 1 partial, 3 monitoring",
  });
  expect(icsEnforcementIndicator({ state: "not_enforcing", ...counts }).status).toBe("error");
  expect(icsEnforcementIndicator({ state: "enforcing", ...counts }).status).toBe("healthy");
  expect(icsEnforcementIndicator({ state: "monitoring", ...counts }).status).toBe("unknown");
  expect(icsEnforcementIndicator({ state: "none", enforcing: 0, partial: 0, notEnforcing: 0, monitoring: 0 }))
    .toEqual({ status: "unknown", label: "ICS protocol enforcement", sublabel: "no ICS protocol rules applied" });
  expect(icsEnforcementIndicator({ state: "unknown", enforcing: 0, partial: 0, notEnforcing: 0, monitoring: 0 }).sublabel)
    .toBe("engine status unknown");
});

test("the effective mode resolves the global mode like the engine", () => {
  expect(formatICSMode(undefined, " Enforce ").label).toBe("inherit (enforce)");
  expect(formatICSMode(undefined, "Learn").label).toBe("inherit (learning)");
  expect(formatICSMode(undefined, "").label).toBe("inherit (learning)");
  expect(formatICSMode("", "enforce").label).toBe("inherit (enforce)");
  expect(formatICSMode("enforce", "learn").label).toBe("enforce");
});
