import { expect, test } from "@playwright/test";

import {
  normalizeICSCoverageList,
  normalizeICSCoverageReport,
  normalizeICSCoverageRule,
  normalizeICSEnforcementHealth,
  sameICSCoverage,
  staticICSCoverage,
} from "../lib/api-ics-coverage";
import {
  coverageViewFromReport,
  describeRuleCoverage,
  formatReason,
  icsEnforcementIndicator,
  type ICSCoverageView,
} from "../app/ics/ics-coverage-model";
import { formatICSMode } from "../app/ics/ics-shared";

// Pure model tests: no page, no server.

const enforcing = { ruleId: "r1", protocol: "modbus", mode: "enforce", state: "enforcing" as const, reasons: [] };
const exclusion = { code: "exclusion-overlap", message: "exclusion 10.0.0.0/24 meets the rule scope", value: "10.0.0.0/24" };

const queue = { code: "queue-unavailable", message: "queue 101 is not bound by this engine", runtime: true };
const decoder = { code: "decoder-disabled", message: "the modbus decoder is off" };

function loaded(candidate: unknown[] | null, applied: unknown[] | null): ICSCoverageView {
  return coverageViewFromReport(
    normalizeICSCoverageReport({
      ...(candidate ? { candidate } : { candidateError: "candidate invalid" }),
      ...(applied ? { applied } : { engineStatusError: "engine unreachable" }),
    }),
  );
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

test("the coverage report keeps each side independent and unknown when unexplained", () => {
  expect(normalizeICSCoverageReport(null)).toEqual({});
  expect(normalizeICSCoverageReport({ candidate: "x", applied: [], appliedAt: "2026-10-26T09:00:00Z", applyError: "nft failed" }))
    .toEqual({ applied: [], appliedAt: "2026-10-26T09:00:00Z", applyError: "nft failed" });
  // An error wins over a list sent beside it.
  expect(normalizeICSCoverageReport({ candidateError: "bad", candidate: [enforcing], engineStatusError: "down", applied: [enforcing] }))
    .toEqual({ candidateError: "bad", engineStatusError: "down" });
  expect(normalizeICSCoverageRule({ ...enforcing, reasons: [{ ...queue, runtime: "yes" }] })?.reasons).toEqual([
    { code: "queue-unavailable", message: queue.message },
  ]);

  const unknownBoth = coverageViewFromReport({});
  expect(unknownBoth).toMatchObject({
    status: "loaded",
    candidate: null,
    candidateError: "not reported by the server",
    applied: null,
    appliedError: "not reported by the server",
  });
  expect(describeRuleCoverage(unknownBoth, "r1").map((l) => l.label)).toEqual(["applied: unknown", "candidate: unavailable"]);
});

test("static coverage drops runtime reasons and recomputes the state", () => {
  const live = { ...enforcing, state: "not_enforcing" as const, reasons: [queue, { ...exclusion, matches: 9 }] };
  expect(staticICSCoverage(live)).toEqual({ ...enforcing, state: "partial", reasons: [exclusion] });
  expect(staticICSCoverage({ ...live, reasons: [queue] }).state).toBe("enforcing");
  expect(staticICSCoverage({ ...live, reasons: [queue, exclusion, decoder] }).state).toBe("not_enforcing");
  expect(staticICSCoverage({ ...live, mode: "learn", reasons: [decoder] })).toEqual({
    ...enforcing,
    mode: "learn",
    state: "monitoring",
    reasons: [decoder],
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

  // A runtime fault is an applied fact, not drift.
  const runtimeOnly = loaded([enforcing], [{ ...enforcing, state: "not_enforcing", reasons: [queue] }]);
  expect(describeRuleCoverage(runtimeOnly, "r1")).toEqual([
    { label: "applied: not enforcing", variant: "error", reasons: [queue] },
  ]);

  const differs = loaded([enforcing], [{ ...enforcing, state: "not_enforcing", reasons: [queue, decoder] }]);
  expect(describeRuleCoverage(differs, "r1")).toEqual([
    { label: "applied: not enforcing", variant: "error", reasons: [queue, decoder] },
    { label: "candidate: enforcing", variant: "success", reasons: [] },
  ]);

  const pending = loaded([enforcing], []);
  expect(describeRuleCoverage(pending, "r1").map((l) => l.label)).toEqual(["not applied", "candidate: enforcing"]);

  const engineDown = loaded([enforcing], null);
  expect(engineDown.status === "loaded" && engineDown.appliedError).toBe("engine unreachable");
  expect(describeRuleCoverage(engineDown, "r1").map((l) => l.label)).toEqual(["applied: unknown", "candidate: enforcing"]);

  const candidateBad = loaded(null, [enforcing]);
  expect(candidateBad.status === "loaded" && candidateBad.candidateError).toBe("candidate invalid");
  expect(describeRuleCoverage(candidateBad, "r1").map((l) => l.label)).toEqual(["applied: enforcing", "candidate: unavailable"]);
});

test("coverage without data never reads as enforcement", () => {
  for (const view of [
    { status: "loading" },
    { status: "unavailable", error: "x" },
  ] as ICSCoverageView[]) {
    const lines = describeRuleCoverage(view, "r1");
    expect(lines).toHaveLength(1);
    expect(lines[0].variant).toBe("neutral");
  }
});

test("reasons name the exclusion, its matches and runtime faults", () => {
  expect(formatReason({ code: "dpi-disabled", message: "DPI is switched off" })).toBe("DPI is switched off");
  expect(formatReason({ code: "domain-exclusion", message: "a domain exclusion can bypass inspection", value: "plc.example", matches: 1 }))
    .toBe("a domain exclusion can bypass inspection (plc.example) \u2014 1 connection exempted since the last apply");
  expect(formatReason({ ...exclusion, matches: 3 }))
    .toBe("exclusion 10.0.0.0/24 meets the rule scope \u2014 3 connections exempted since the last apply");
  expect(formatReason(exclusion)).toBe("exclusion 10.0.0.0/24 meets the rule scope");
  // Matches belong to exclusions only.
  expect(formatReason({ ...decoder, matches: 2 })).toBe(decoder.message);
  expect(formatReason(queue)).toBe(`Running engine: ${queue.message}`);
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
