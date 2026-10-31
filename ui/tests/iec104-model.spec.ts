import { expect, test } from "@playwright/test";

import { parseICSEvidence } from "../lib/api-iec104";
import { normalizeFirewallRule } from "../lib/api-normalize";
import type { TelemetryEvent } from "../lib/api";
import { effectiveICSDecoders } from "../app/firewall/firewall-utils";
import { describeICSEvidence } from "../app/events/iec104-evidence";
import {
  buildIEC104RuleICS,
  iec104TypeInfo,
  iec104DraftFrom,
  summarizeIEC104,
  type IEC104Draft,
} from "../app/ics/iec104";
import {
  buildICSRuleUpdate,
  formatICSMode,
} from "../app/ics/ics-shared";
import { iec104HealthIndicator } from "../app/ics/iec104-health";

// Pure model tests: no page, no server.

const empty: IEC104Draft = iec104DraftFrom(undefined);

test("command predicates normalize, round-trip and clear with merge-patch nulls", () => {
  for (const typeId of [45, 46, 47, 58, 59, 60]) {
    const states = [45, 58].includes(typeId) ? [0, 1] : [1, 2];
    const rule = normalizeFirewallRule({
      id: "command",
      action: "ALLOW",
      ics: { protocol: "iec104", typeIds: [typeId], commandStates: states, commandQualifiers: [0, 31] },
    });
    const draft = iec104DraftFrom(rule.ics);
    expect(draft.commandStates).toBe(states.join(", "));
    expect(draft.commandQualifiers).toBe("0, 31");
    expect(buildIEC104RuleICS(draft, "", "ALLOW")).toMatchObject({ ok: true, ics: rule.ics });
    expect(buildIEC104RuleICS({ ...draft, commandStates: "", commandQualifiers: "" }, "", "ALLOW", rule.ics))
      .toMatchObject({ ok: true, ics: { commandStates: null, commandQualifiers: null } });
  }
  expect(iec104DraftFrom({ protocol: "modbus", commandStates: [1], commandQualifiers: [0] }))
    .toMatchObject({ commandStates: "", commandQualifiers: "" });
  expect(normalizeFirewallRule({ ics: { protocol: "iec104" } }).ics).not.toHaveProperty("commandStates");
  expect(normalizeFirewallRule({ ics: { protocol: "iec104" } }).ics).not.toHaveProperty("commandQualifiers");
});

test("command predicates validate type domains and integer lists for every action", () => {
  const bad: Array<[Partial<IEC104Draft>, RegExp]> = [
    [{ typeIds: "", commandStates: "1" }, /require explicit Type IDs/],
    [{ typeIds: "", commandQualifiers: "0" }, /require explicit Type IDs/],
    [{ typeIds: "45, 100", commandStates: "1" }, /require explicit Type IDs/],
    [{ typeIds: "48", commandQualifiers: "1" }, /require explicit Type IDs/],
    [{ typeIds: "45, 46", commandStates: "1" }, /cannot mix/],
    [{ typeIds: "58, 60", commandStates: "1" }, /cannot mix/],
    [{ typeIds: "45", commandStates: "2" }, /must be in 0-1/],
    [{ typeIds: "46", commandStates: "0" }, /must be in 1-2/],
    [{ typeIds: "47", commandStates: "3" }, /integer from 0 to 2/],
    [{ typeIds: "60", commandStates: "1.5" }, /integer/],
    [{ typeIds: "59", commandStates: "-1" }, /integer/],
    [{ typeIds: "45", commandStates: "null" }, /integer/],
    [{ typeIds: "45", commandStates: "[]" }, /integer/],
    [{ typeIds: "45", commandStates: ", " }, /at least one integer/],
    [{ typeIds: "45", commandQualifiers: "32" }, /integer from 0 to 31/],
    [{ typeIds: "45", commandQualifiers: "-1" }, /integer/],
    [{ typeIds: "45", commandQualifiers: "1.5" }, /integer/],
    [{ typeIds: "45", commandQualifiers: "1, null" }, /integer/],
    [{ typeIds: "45", commandQualifiers: "[]" }, /integer/],
    [{ typeIds: "45", commandQualifiers: ", " }, /at least one integer/],
  ];
  for (const action of ["ALLOW", "DENY", "RESET", "RATE_LIMIT", "TAG"] as const) {
    for (const [patch, error] of bad) {
      const result = buildIEC104RuleICS({ ...empty, ...patch }, "monitor", action);
      expect(result.ok, JSON.stringify({ action, patch })).toBe(false);
      if (!result.ok) expect(result.error).toMatch(error);
    }
  }
  for (const [types, states] of [["45, 58", "0, 1"], ["46, 47, 59, 60", "1, 2"]]) {
    expect(buildIEC104RuleICS({ ...empty, typeIds: types, commandStates: states, commandQualifiers: "0, 31" }, "", "ALLOW").ok).toBe(true);
  }
  // QU alone can span both state domains. Duplicates follow COT list semantics.
  expect(buildIEC104RuleICS({ ...empty, typeIds: "45, 46", commandQualifiers: "0, 0, 31" }, "", "ALLOW"))
    .toMatchObject({ ok: true, ics: { commandQualifiers: [0, 0, 31] } });
});

test("command summaries keep numeric bounds and type-specific state meanings", () => {
  for (const [types, states, label] of [
    [[45, 58], [0, 1], "SCS 0 (off), 1 (on)"],
    [[46, 59], [1, 2], "DCS 1 (off), 2 (on)"],
    [[47, 60], [1, 2], "RCS 1 (lower), 2 (higher)"],
    [[46, 47], [1], "DCS 1 (off); RCS 1 (lower)"],
  ] as const) {
    const summary = summarizeIEC104({ protocol: "iec104", typeIds: [...types], commandStates: [...states], commandQualifiers: [0, 31] });
    expect(summary.types).toContain(`state ${label}`);
    expect(summary.types).toContain("QU 0,31");
  }
});

test("EU breaker rule serialises to the IEC 104 rule wire shape", () => {
  const draft: IEC104Draft = {
    ...empty,
    typeIds: "46",
    classes: ["control"],
    direction: "request",
    ca: "1",
    ioa: "2001",
  };
  const res = buildIEC104RuleICS(draft, "enforce", "ALLOW");
  expect(res.ok).toBe(true);
  if (!res.ok) return;
  expect(JSON.stringify(res.ics)).toBe(
    '{"protocol":"iec104","typeIds":[46],"classes":["control"],"direction":"request","ca":[1],"ioa":[{"start":2001,"end":2001}],"readOnly":false,"mode":"enforce"}',
  );
});

test("an empty draft emits no list fields and no forbidden keys", () => {
  const res = buildIEC104RuleICS({ ...empty, readOnly: true }, "monitor", "ALLOW");
  expect(res).toEqual({
    ok: true,
    ics: { protocol: "iec104", readOnly: true, mode: "monitor" },
  });
});

test("inherited mode display resolves the global mode without inventing a rule override", () => {
  expect(formatICSMode(undefined, "enforce")).toEqual({
    label: "Inherit (Enforce)",
    effectiveMode: "enforce",
    inherited: true,
  });
  expect(formatICSMode(undefined, undefined)).toEqual({
    label: "Inherit (Monitor (safe))",
    effectiveMode: "monitor",
    inherited: true,
  });
  expect(formatICSMode("monitor", "enforce")).toEqual({
    label: "Monitor (safe)",
    effectiveMode: "monitor",
    inherited: false,
  });

  const generic = buildICSRuleUpdate(
    "modbus",
    "",
    "",
    "",
    "",
    false,
    false,
    "",
  );
  expect(generic.mode).toBeUndefined();
  expect(JSON.stringify(generic)).not.toContain('"mode"');
});

test("saving an inherited IEC 104 mode omits the mode override", () => {
  const res = buildIEC104RuleICS(
    { ...empty, readOnly: true },
    "",
    "ALLOW",
    undefined,
    "enforce",
  );
  expect(res).toEqual({
    ok: true,
    ics: { protocol: "iec104", readOnly: true },
  });
  const unsupported = buildIEC104RuleICS(
    { ...empty, typeIds: "104" },
    "",
    "ALLOW",
    undefined,
    "enforce",
  );
  expect(unsupported.ok).toBe(false);
});

test("client checks mirror the server IEC 104 field ranges", () => {
  const bad: Array<[Partial<IEC104Draft>, RegExp]> = [
    [{ typeIds: "0" }, /outside 1-255/],
    [{ typeIds: "256" }, /outside 1-255/],
    [{ typeIds: "4x" }, /not a whole number/],
    [{ ca: "65535" }, /broadcast/],
    [{ ca: "70000" }, /outside 0-65534/],
    [{ ioa: "16777216" }, /outside 0-16777215/],
    [{ ioa: "10-5" }, /starts after it ends/],
    [{ ioa: "1-10, 10-20" }, /overlap/],
    [{ ioa: "5, 5" }, /overlap/],
  ];
  for (const [patch, msg] of bad) {
    const res = buildIEC104RuleICS({ ...empty, ...patch }, "enforce", "DENY");
    expect(res.ok, JSON.stringify(patch)).toBe(false);
    if (!res.ok) expect(res.error).toMatch(msg);
  }
  const ok = buildIEC104RuleICS(
    { ...empty, typeIds: "46, 46", ca: "0, 65534", ioa: "0-9, 10, 16777215" },
    "enforce",
    "DENY",
  );
  expect(ok.ok).toBe(true);
  if (ok.ok) {
    expect(ok.ics.typeIds).toEqual([46]);
    expect(ok.ics.ioa).toEqual([
      { start: 0, end: 9 },
      { start: 10, end: 10 },
      { start: 16777215, end: 16777215 },
    ]);
  }
});

test("allow rules may name only decoded Type IDs unless monitoring", () => {
  const draft = { ...empty, typeIds: "46, 104" };
  const allow = buildIEC104RuleICS(draft, "enforce", "ALLOW");
  expect(allow.ok).toBe(false);
  if (!allow.ok) expect(allow.error).toMatch(/104 is not decoded/);
  expect(buildIEC104RuleICS(draft, "enforce", "DENY").ok).toBe(true);
  expect(buildIEC104RuleICS(draft, "monitor", "ALLOW").ok).toBe(true);
});

test("single-point monitor Type IDs are decoded and may be allowed", () => {
  expect(iec104TypeInfo(1)).toMatchObject({ name: "M_SP_NA_1 single point", cls: "monitor", descriptor: true });
  expect(iec104TypeInfo(30)).toMatchObject({ name: "M_SP_TB_1 single point, time", cls: "monitor", descriptor: true });
  const res = buildIEC104RuleICS({ ...empty, typeIds: "1, 30" }, "enforce", "ALLOW");
  expect(res).toMatchObject({ ok: true, ics: { typeIds: [1, 30] } });
});

test("an update clears stored IEC fields with null", () => {
  const existing = { protocol: "iec104", typeIds: [46], ca: [1], mode: "enforce" as const };
  const draft = iec104DraftFrom(existing);
  expect(draft.ca).toBe("1");
  const res = buildIEC104RuleICS({ ...draft, ca: "" }, "enforce", "ALLOW", existing);
  expect(res).toMatchObject({ ok: true, ics: { ca: null } });
  expect(buildIEC104RuleICS({ ...draft, ca: "2" }, "enforce", "ALLOW", existing).ok).toBe(true);
  // A protocol change replaces the predicate, so nothing is guarded.
  expect(
    buildIEC104RuleICS({ ...draft, ca: "" }, "enforce", "ALLOW", { protocol: "modbus", functionCode: [3] }).ok,
  ).toBe(true);
});

test("normalisation keeps IEC fields and key presence", () => {
  const rule = normalizeFirewallRule({
    id: "cc-rtu-breaker-command",
    action: "ALLOW",
    ics: {
      protocol: "iec104",
      typeIds: [46],
      classes: ["control", "bogus"],
      direction: "request",
      ca: [1],
      ioa: [{ start: 2001, end: 2001 }],
      mode: "enforce",
    },
  });
  expect(rule.ics).toEqual({
    protocol: "iec104",
    typeIds: [46],
    classes: ["control"],
    direction: "request",
    ca: [1],
    ioa: [{ start: 2001, end: 2001 }],
    mode: "enforce",
  });
  expect(normalizeFirewallRule({ id: "a", action: "ALLOW", ics: {} }).ics).toEqual({});
  expect(
    normalizeFirewallRule({ id: "b", action: "ALLOW", ics: { protocol: "modbus", readOnly: true } }).ics,
  ).toEqual({ protocol: "modbus", readOnly: true });
});

test("an unset ICS decoder is effectively enabled", () => {
  expect(effectiveICSDecoders(undefined).iec104).toBe(true);
  expect(effectiveICSDecoders({}).iec104).toBe(true);
  expect(effectiveICSDecoders({ iec104: false }).iec104).toBe(false);
  expect(effectiveICSDecoders({ modbus: true, custom: false })).toMatchObject({
    modbus: true,
    custom: false,
    dnp3: true,
  });
});

function ev(kind: string, attributes: Record<string, unknown>): TelemetryEvent {
  return { id: 1, flowId: "f", proto: "iec104", kind, attributes, timestamp: "2026-11-07T09:15:02Z" };
}

test("evidence events decode with typed attributes", () => {
  const decision = parseICSEvidence(
    ev("ics.decision", {
      session_id: "ab-1",
      decision: "deny",
      ruleId: "deny-other-iec104",
      action: "DENY",
      mode: "enforce",
      reason: "rule",
      apdu_id: "ab-1/c/16",
      type_id: 45,
      ca: 1,
      ioa: 2002,
      select: false,
      direction: "request",
    }),
  );
  expect(decision?.kind).toBe("ics.decision");
  expect(parseICSEvidence(ev("ics.decision", { session_id: "x", decision: "maybe", reason: "rule" }))).toBeNull();
  expect(parseICSEvidence({ ...ev("ics.verdict", { outcome: "dropped" }), proto: "modbus" })).toBeNull();

  const verdict = describeICSEvidence(
    ev("ics.verdict", { session_id: "ab-1", outcome: "dropped", apdu_ids: ["ab-1/c/16", "ab-1/c/32"] }),
  );
  expect(verdict?.message).toBe("Dropped 2 APDUs of an aborted session");
  expect(verdict?.rows).toContainEqual({ label: "Trigger APDU", value: "none (timeout, queue or transport abort)" });

  const reset = describeICSEvidence(
    ev("ics.session", { session_id: "ab-1", outcome: "reset_failed", target: "server", error: "sendto: EPERM" }),
  );
  expect(reset?.severity).toBe("critical");
  expect(reset?.message).toBe("IEC 104 reset failed to server: sendto: EPERM");

  const allowed = describeICSEvidence(
    ev("ics.decision", { session_id: "ab-1", decision: "allow", ruleId: "r", reason: "rule" }),
  );
  expect(allowed?.alert).toBe(false);
});

test("a strict nonconformant decision shows its conformance codes", () => {
  const strict = describeICSEvidence(
    ev("ics.decision", {
      session_id: "ab-1",
      decision: "deny",
      ruleId: "",
      action: "DENY",
      mode: "enforce",
      reason: "nonconformant",
      conformance: ["iec104.reserved_bits", "iec104.role"],
      apdu_id: "ab-1/c/16",
      type_id: 45,
      ca: 1,
      ioa: 2002,
    }),
  );
  expect(strict?.alert).toBe(true);
  expect(strict?.message).toBe(
    "deny: type 45 CA 1 IOA 2002 (nonconformant under strict parsing, envelope default; iec104.reserved_bits, iec104.role)",
  );
  expect(strict?.rows).toContainEqual({ label: "Reason", value: "nonconformant under strict parsing" });
  expect(strict?.rows).toContainEqual({ label: "Conformance", value: "iec104.reserved_bits, iec104.role" });

  // Tolerant parsing keeps the codes on an ordinary rule decision.
  const tolerant = parseICSEvidence(
    ev("ics.decision", { session_id: "ab-1", decision: "allow", ruleId: "r", reason: "rule", conformance: ["iec104.time", 7] }),
  );
  expect(tolerant?.kind === "ics.decision" && tolerant.attrs.conformance).toEqual(["iec104.time"]);
  const plain = describeICSEvidence(
    ev("ics.decision", { session_id: "ab-1", decision: "allow", ruleId: "r", reason: "rule" }),
  );
  expect(plain?.message).toBe("allow: APDU (matched rule, r)");
  expect(plain?.rows.map((r) => r.label)).not.toContain("Conformance");

  // The engine no longer emits role or unsupported; a reason without a
  // label is shown raw instead of hiding the decision.
  for (const reason of ["role", "unsupported", "future"]) {
    const raw = describeICSEvidence(
      ev("ics.decision", { session_id: "ab-1", decision: "deny", ruleId: "", reason }),
    );
    expect(raw?.rows, reason).toContainEqual({ label: "Reason", value: reason });
  }
  expect(parseICSEvidence(ev("ics.decision", { session_id: "ab-1", decision: "deny", ruleId: "" }))).toBeNull();
});

test("health indicator names IEC 104 only while an IEC 104 envelope is active", () => {
  expect(iec104HealthIndicator({ active: true, healthy: false, reason: "queue bind failed" })).toEqual({
    status: "degraded", label: "IEC 104 enforcement unhealthy", sublabel: "queue bind failed",
  });
  // Without an IEC 104 envelope only a failed reset of a picked-up Modbus
  // or DNP3 connection makes the object unhealthy.
  expect(iec104HealthIndicator({ active: false, healthy: false, reason: "picked-up connection 10.0.0.2:40000 > 10.0.0.3:502: send failed" })).toEqual({
    status: "degraded", label: "ICS connection reset unhealthy", sublabel: "picked-up connection 10.0.0.2:40000 > 10.0.0.3:502: send failed",
  });
  expect(iec104HealthIndicator({ active: false, healthy: false, reason: "" }).sublabel).toBe("no reason reported");
  expect(iec104HealthIndicator({ active: true, healthy: true, reason: "" }).label).toBe("IEC 104 enforcement active");
  expect(iec104HealthIndicator({ active: false, healthy: true, reason: "" }).label).toBe("IEC 104 enforcement inactive");
  expect(iec104HealthIndicator(undefined)).toEqual({ status: "unknown", label: "IEC 104 enforcement", sublabel: "status unavailable" });
});
