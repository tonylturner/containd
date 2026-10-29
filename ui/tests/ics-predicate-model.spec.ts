import { expect, test } from "@playwright/test";
import { buildRuleICS } from "../app/firewall/firewall-ics-fields";
import { icsDraftFrom } from "../app/firewall/firewall-rule-forms";
import { summarizeGenericICS, effectivePredicate } from "../app/ics/ics-shared";
import { normalizeFirewallRule } from "../lib/api-normalize";
import type { ICSPredicate } from "../lib/api";

const predicates: ICSPredicate[] = [
  { protocol: "dnp3", functionCode: [0], masters: [0, 65519], outstations: [0], groups: [0, 255], variations: [0, 255], addresses: ["0-4294967295"], direction: "request", readOnly: false, writeOnly: false },
  { protocol: "cip", objectClasses: [0, 65535], instances: [0, 65535], attributes: [0, 65535], readOnly: false, writeOnly: false },
  { protocol: "cip", tags: ["A.B", "Program:Main.Motor"], readOnly: false, writeOnly: false },
  { protocol: "iec104", typeIds: [46], cot: [1, 63], originators: [0, 255], negative: false, test: false, selectExecute: "execute", readOnly: false },
];

for (const ics of predicates) {
  test(`normalizer, draft, save and preview preserve ${JSON.stringify(ics)}`, () => {
    const normalized = normalizeFirewallRule({ id: "rule", action: "ALLOW", ics }).ics;
    expect(normalized).toEqual(ics);
    const built = buildRuleICS({ ...icsDraftFrom(normalized, ""), action: "ALLOW", existing: normalized });
    expect(built).toEqual({ ok: true, ics });
    if (built.ok) expect(effectivePredicate(built.ics)).toEqual(ics);
  });

  test(`clearing every ${JSON.stringify(ics)} selector emits null only in PATCH`, () => {
    const draft = icsDraftFrom({ protocol: ics.protocol }, "");
    const built = buildRuleICS({ ...draft, existing: ics, action: "ALLOW" });
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    const fields = Object.keys(ics).filter((key) => !["protocol", "readOnly", "writeOnly"].includes(key));
    for (const key of fields) expect(built.ics).toHaveProperty(key, null);
    expect(effectivePredicate(built.ics)).toEqual({
      protocol: ics.protocol, readOnly: false, ...(ics.protocol !== "iec104" ? { writeOnly: false } : {}),
    });
  });
}

test("new generic field errors block the shared builder", () => {
  for (const [protocol, key, value] of [
    ["dnp3", "masters", "65520"], ["dnp3", "outstations", "-1"],
    ["dnp3", "groups", "256"], ["dnp3", "variations", "1.1"],
    ["cip", "instances", "65536"], ["cip", "attributes", "no"],
    ["cip", "tags", "Motor[0]"], ["cip", "tags", "A..B"],
    ["cip", "tags", "A.Program:Main"], ["cip", "tags", "A".repeat(41)],
  ]) {
    const draft = icsDraftFrom({ protocol }, "");
    draft.selectors = { ...draft.selectors, [key]: value };
    expect(buildRuleICS({ ...draft, action: "ALLOW" }).ok, `${key}=${value}`).toBe(false);
  }
  for (const [protocol, addresses, groups] of [["dnp3", "4294967296", "50"], ["dnp3", "10-0", "50"], ["dnp3", "1", ""], ["cip", "1", ""]]) {
    const draft = icsDraftFrom({ protocol }, "");
    expect(buildRuleICS({ ...draft, addresses, selectors: { ...draft.selectors, groups }, action: "ALLOW" }).ok).toBe(false);
  }
  const draft = icsDraftFrom({ protocol: "cip", objectClasses: [4], tags: ["A"] }, "");
  expect(buildRuleICS({ ...draft, action: "ALLOW" }).ok).toBe(false);
});

test("IEC new ranges and select/execute capability are checked", () => {
  for (const patch of [{ cot: "0" }, { cot: "64" }, { originators: "256" }, { typeIds: "51", selectExecute: "select" as const }, { typeIds: "64", selectExecute: "execute" as const }]) {
    const draft = icsDraftFrom({ protocol: "iec104" }, "");
    expect(buildRuleICS({ ...draft, iec: { ...draft.iec, ...patch }, action: "ALLOW" }).ok).toBe(false);
  }
  const draft = icsDraftFrom({ protocol: "iec104", selectExecute: "select" }, "");
  expect(buildRuleICS({ ...draft, action: "ALLOW" }).ok).toBe(true);
});

test("review summaries expose logical and symbolic constraints, including zero", () => {
  expect(summarizeGenericICS(predicates[0])).toContain("masters=0, 65519");
  expect(summarizeGenericICS(predicates[1])).toContain("instances=0, 65535");
  expect(summarizeGenericICS(predicates[2])).toContain("tags=A.B, Program:Main.Motor");
});
