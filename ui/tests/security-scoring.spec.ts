import { expect, test } from "@playwright/test";

import type { Conduit } from "../lib/api";
import { mapZone, scoreZone } from "../lib/security-scoring";
import { securityChecks } from "./fixtures/security";

const admitted: Conduit = {
  from: "OT-1", to: "dmz",
  state: "allow", ids: "enabled", proto: [], traffic: { state: "unavailable" as const, reason: "enforcement disabled" }, checks: securityChecks,
  rules: [], gaps: [], mitre: [], defaultDeny: true,
  tlsEnforced: false, protoWhitelist: true, mfaRequired: false,
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
      expect(scores.map((score) => score.sl_a)).toEqual([0, 0]);
      for (const id of ["SR-5.1", "SR-2.8", "SR-5.2"]) {
        expect(scores.map((score) => score.checks.find((check) => check.id === id)?.auto)).toEqual([true, false]);
      }
    }
  });
}

test("authentication evidence stays unknown regardless of zone-name case", () => {
  for (const name of ["internet", "Internet", "INTERNET"]) {
    const zone = mapZone({ name });
    expect(zone.id).toBe(name);
    const score = scoreZone(zone, [{ ...admitted, from: name }]);
    expect(score.checks.find((check) => check.id === "SR-1.1")).toMatchObject({ auto: false, met: false, provenance: "unknown" });
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
    expect(zones.map((zone) => scoreZone(zone, entries).checks.find(c => c.id === "SR-5.2")?.met)).toEqual([true, false, false]);
  }
});

test("names, global settings and port hints never become verified passes", () => {
  for (const name of ["internet", "mgmt", "trusted", "OT-1"]) {
    const { sl_a, checks } = scoreZone(mapZone({ name }), [{ ...admitted, from: name }]);
    expect(sl_a).toBe(0);
    for (const id of ["SR-1.1", "SR-3.3", "SR-1.2", "SR-3.1", "SR-2.8", "SR-3.2"]) {
      const check = checks.find(c => c.id === id)!;
      expect(check.met).toBe(false);
      expect(check.provenance).not.toBe("configured");
      expect(check.reason.length).toBeGreaterThan(0);
    }
    expect(checks.find(c => c.id === "SR-5.2")).toMatchObject({ met: true, provenance: "configured" });
  }
});

test("empty and blocked-only active conduit sets provide no active-control evidence", () => {
  for (const conduits of [[], [{ ...admitted, state: "block" as const }]]) {
    const { checks } = scoreZone(mapZone({ name: "OT-1" }), conduits);
    for (const id of ["SR-1.2", "SR-3.1", "SR-5.4", "SR-1.13", "SR-3.2", "SR-5.4b"]) {
      expect(checks.find(c => c.id === id)).toMatchObject({ met: false, auto: false, provenance: "unknown" });
    }
  }
});

test("operator overrides keep their explicit provenance and never claim verification", () => {
  const zone = mapZone({ name: "ot", slOverrides: { "SR-1.1": true } });
  const { checks } = scoreZone(zone, []);
  expect(checks.find(c => c.id === "SR-1.1")).toMatchObject({ met: true, auto: false, overridden: true, provenance: "configured" });
  expect(checks.find(c => c.id === "SR-1.1")?.reason).toContain("not independently verified");
});

test("an unrestricted host ALLOW alongside TCP/443 cannot pass protocol whitelisting", () => {
  // The API's all-grants check leaves the mixed policy unproved. A listed
  // HTTPS service alone says nothing about the host's unrestricted grant.
  const conduit: Conduit = {
    ...admitted, from: "lan", to: "wan", state: "partial",
    proto: [{ n: "HTTPS", t: "allowed" }], protoWhitelist: false,
    rules: ["ALLOW ALL from LAN to WAN", "ALLOW HTTPS from LAN to WAN"],
    checks: { ...securityChecks, protoWhitelist: {
      provenance: "unknown",
      reason: "A matching ALLOW from 192.0.2.1/32 has no explicit transport restriction.",
    } },
  };
  for (const protoWhitelist of [false, true]) {
    const { checks } = scoreZone(mapZone({ name: "lan" }), [{ ...conduit, protoWhitelist }]);
    expect(checks.find(c => c.id === "SR-5.4")).toMatchObject({ met: false, provenance: "unknown" });
  }
});
