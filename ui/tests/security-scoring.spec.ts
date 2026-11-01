import { expect, test } from "@playwright/test";

import type { Conduit, ConduitMap } from "../lib/api";
import { mapZone, scoreZone } from "../lib/security-scoring";

const admitted: Conduit = {
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
    const conduits: ConduitMap = {
      "OT-1→dmz": admitted,
      [`${other}→dmz`]: unprotected,
      // An incoming conduit must not affect the destination's score.
      "dmz→OT-1": unprotected,
    };
    for (const entries of [Object.entries(conduits), Object.entries(conduits).reverse()]) {
      const scores = zones.map((zone) => scoreZone(zone, Object.fromEntries(entries)));
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
    const score = scoreZone(zone, { [`${name}→dmz`]: admitted });
    expect(score.checks.find((check) => check.id === "SR-1.1")?.auto).toBe(false);
    expect(score.sl_a).toBe(0);
  }
});
