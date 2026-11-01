import { expect, test } from "@playwright/test";

import type { Conduit } from "../lib/api";
import { mapZone, scoreZone } from "../lib/security-scoring";

const admitted: Conduit = {
  from: "OT-1", to: "dmz",
  state: "allow", ids: "full", proto: [], traffic: 0,
  rules: [], gaps: [], mitre: [], defaultDeny: true,
  tlsEnforced: true, protoWhitelist: true, mfaRequired: false,
  auditLogged: true, avEnabled: false,
};
const unprotected: Conduit = { ...admitted, defaultDeny: false, auditLogged: false };

test("zone identities preserve case and punctuation exactly", () => {
  const names = ["OT-1", "ot 1", "ot_1", "ot-1"];
  const zones = names.map((name) => mapZone({ name }));
  expect(zones.map((zone) => zone.id)).toEqual(names);
  expect(new Set(zones.map((zone) => zone.id)).size).toBe(names.length);
});

for (const other of ["ot 1", "ot_1", "ot-1"]) {
  test(`OT-1 and ${other} score only their own outbound conduits`, () => {
    const zones = ["OT-1", other].map((name) => mapZone({ name, slTarget: 2 }));
    const conduits: Conduit[] = [
      admitted,
      { ...unprotected, from: other },
      // An incoming conduit must not affect the destination's score.
      { ...unprotected, from: "dmz", to: "OT-1" },
    ];
    for (const entries of [conduits, [...conduits].reverse()]) {
      const scores = zones.map((zone) => scoreZone(zone, entries));
      expect(scores.map((score) => score.sl_a)).toEqual([2, 0]);
      for (const id of ["SR-5.1", "SR-2.8", "SR-5.2"]) {
        expect(scores.map((score) => score.checks.find((check) => check.id === id)?.auto)).toEqual([true, false]);
      }
    }
  });
}

test("Internet classification stays case-insensitive without changing identity", () => {
  for (const name of ["internet", "Internet", "INTERNET"]) {
    const zone = mapZone({ name });
    expect(zone.id).toBe(name);
    const score = scoreZone(zone, [{ ...admitted, from: name }]);
    expect(score.checks.find((check) => check.id === "SR-1.1")?.auto).toBe(false);
    expect(score.sl_a).toBe(0);
  }
});

test("arrow-containing zone names score only their exact outbound conduits", () => {
  const zones = ["a→b", "a", "b"].map((name) => mapZone({ name, slTarget: 2 }));
  const conduits: Conduit[] = [
    { ...admitted, from: "a→b", to: "b" },
    { ...unprotected, from: "a", to: "b" },
    { ...unprotected, from: "b", to: "a→b" },
  ];
  for (const entries of [conduits, [...conduits].reverse()]) {
    expect(zones.map((zone) => scoreZone(zone, entries).sl_a)).toEqual([2, 0, 0]);
  }
});
