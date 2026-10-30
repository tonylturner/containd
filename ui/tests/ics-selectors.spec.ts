import { expect, test } from "@playwright/test";
import { buildICSRuleUpdate, selectorFieldError } from "../app/ics/ics-shared";
import { buildRuleICS } from "../app/firewall/firewall-ics-fields";
import { icsDraftFrom } from "../app/firewall/firewall-rule-forms";
import { normalizeFirewallRule } from "../lib/api-normalize";
import type { ICSPredicate } from "../lib/api";

for (const [text, codes] of [["", undefined], [" ", undefined], ["3,", [3]], [",,3,,", [3]], ["0", [0]], ["0x4c", [76]]] as const) {
  test(`both builders preserve code input ${JSON.stringify(text)}`, () => {
    const generic = buildICSRuleUpdate("modbus", text, "", "", "", false, false, "");
    const firewall = buildRuleICS({ ...icsDraftFrom({ protocol: "modbus" }, ""), functionCodes: text, action: "ALLOW" });
    expect(firewall).toEqual({ ok: true, ics: generic });
    expect(generic.functionCode).toEqual(codes);
  });
}

for (const text of ["-1", "256", "3.2", "3,no", "Infinity", "3e1"]) {
  test(`invalid code ${text} is rejected, not clamped or dropped`, () => {
    expect(selectorFieldError("modbus", text, "", "")).toContain("integer from 0 to 255");
    expect(buildRuleICS({ ...icsDraftFrom({ protocol: "modbus" }, ""), functionCodes: text, action: "ALLOW" }).ok).toBe(false);
  });
}

test("normalization and drafts retain every predicate field", () => {
  const predicates: ICSPredicate[] = [
    { protocol: "modbus", functionCode: [0, 3], unitId: 0, addresses: ["0-10"], readOnly: true, writeOnly: false, direction: "request", mode: "monitor" },
    { protocol: "cip", functionCode: [14], objectClasses: [0, 4, 65535], direction: "response", readOnly: false, writeOnly: true, mode: "enforce" },
    { protocol: "iec104", typeIds: [1], classes: ["monitor"], ca: [0], ioa: [{ start: 0, end: 0 }], direction: "response", readOnly: true, mode: "enforce" },
  ];
  for (const ics of predicates) {
    const normalized = normalizeFirewallRule({ id: "a", action: "ALLOW", ics }).ics;
    expect(normalized).toEqual(ics);
    const draft = icsDraftFrom(normalized, ics.mode ?? "");
    expect(buildRuleICS({ ...draft, action: "ALLOW", existing: normalized })).toEqual({ ok: true, ics });
  }
});

test("cleared generic selectors are explicit and direction survives", () => {
  for (const ics of [
    { protocol: "modbus", functionCode: [3], unitId: 0, addresses: ["0-10"], direction: "request" },
    { protocol: "cip", functionCode: [14], objectClasses: [4], direction: "response" },
  ] satisfies ICSPredicate[]) {
    const built = buildRuleICS({ ...icsDraftFrom(ics, ""), functionCodes: "", unitId: "", addresses: "", objectClasses: "", existing: ics, action: "ALLOW" });
    expect(built).toMatchObject({ ok: true, ics: { protocol: ics.protocol, functionCode: null, direction: ics.direction } });
    if (built.ok) {
      expect(built.ics?.unitId).toBe(ics.protocol === "modbus" ? null : undefined);
      expect(built.ics?.objectClasses).toBe(ics.protocol === "cip" ? null : undefined);
    }
  }
});

test("invalid units and object classes fail without dropping a restriction", () => {
  for (const unit of ["-1", "256", "1.5", "1,2", "no"]) {
    expect(selectorFieldError("modbus", "", unit, "")).toContain("Unit ID");
    expect(() => buildICSRuleUpdate("modbus", "", "", unit, "", false, false, "")).toThrow();
  }
  for (const classes of ["-1", "65536", "4.5", "0x4z", "4,no"]) {
    expect(selectorFieldError("cip", "", "", classes)).toContain("Object classes");
  }
});

test("a hidden legacy unit selector on DNP3 or CIP blocks save until removed", () => {
  for (const protocol of ["dnp3", "cip"]) {
    const existing: ICSPredicate = { protocol, unitId: 0, direction: "request" };
    expect(buildRuleICS({ ...icsDraftFrom(existing, ""), existing, action: "ALLOW" })).toMatchObject({ ok: false, error: expect.stringContaining("unitId") });
    expect(buildRuleICS({ ...icsDraftFrom(existing, ""), unitId: "", existing, action: "ALLOW" })).toMatchObject({ ok: true, ics: { unitId: null } });
  }
});
