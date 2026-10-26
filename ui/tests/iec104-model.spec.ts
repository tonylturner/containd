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
  type IEC104Draft,
} from "../app/ics/iec104";
import {
  buildICSRuleUpdate,
  formatICSMode,
} from "../app/ics/ics-shared";

// Pure model tests: no page, no server.

const empty: IEC104Draft = iec104DraftFrom(undefined);

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
  const res = buildIEC104RuleICS({ ...empty, readOnly: true }, "learn", "ALLOW");
  expect(res).toEqual({
    ok: true,
    ics: { protocol: "iec104", readOnly: true, mode: "learn" },
  });
});

test("inherited mode display resolves the global mode without inventing a rule override", () => {
  expect(formatICSMode(undefined, "enforce")).toEqual({
    label: "inherit (enforce)",
    effectiveMode: "enforce",
    inherited: true,
  });
  expect(formatICSMode(undefined, undefined)).toEqual({
    label: "inherit (learning)",
    effectiveMode: "learn",
    inherited: true,
  });
  expect(formatICSMode("learn", "enforce")).toEqual({
    label: "learning",
    effectiveMode: "learn",
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

test("allow rules may name only decoded Type IDs unless learning", () => {
  const draft = { ...empty, typeIds: "46, 104" };
  const allow = buildIEC104RuleICS(draft, "enforce", "ALLOW");
  expect(allow.ok).toBe(false);
  if (!allow.ok) expect(allow.error).toMatch(/104 is not decoded/);
  expect(buildIEC104RuleICS(draft, "enforce", "DENY").ok).toBe(true);
  expect(buildIEC104RuleICS(draft, "learn", "ALLOW").ok).toBe(true);
});

test("single-point monitor Type IDs are decoded and may be allowed", () => {
  expect(iec104TypeInfo(1)).toMatchObject({ name: "M_SP_NA_1 single point", cls: "monitor", descriptor: true });
  expect(iec104TypeInfo(30)).toMatchObject({ name: "M_SP_TB_1 single point, time", cls: "monitor", descriptor: true });
  const res = buildIEC104RuleICS({ ...empty, typeIds: "1, 30" }, "enforce", "ALLOW");
  expect(res).toMatchObject({ ok: true, ics: { typeIds: [1, 30] } });
});

test("an update that would clear a stored IEC field is refused", () => {
  const existing = { protocol: "iec104", typeIds: [46], ca: [1], mode: "enforce" as const };
  const draft = iec104DraftFrom(existing);
  expect(draft.ca).toBe("1");
  const res = buildIEC104RuleICS({ ...draft, ca: "" }, "enforce", "ALLOW", existing);
  expect(res.ok).toBe(false);
  if (!res.ok) expect(res.error).toMatch(/cannot clear ca/);
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
