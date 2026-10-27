import assert from "node:assert/strict";
import { test } from "node:test";
import { createElement, type ReactNode } from "react";

const { renderToStaticMarkup } = require("react-dom/server") as {
  renderToStaticMarkup: (node: ReactNode) => string;
};

import { iec104DraftFrom } from "../ics/iec104";
import { UNSUPPORTED_ADDRESSES } from "../ics/ics-shared";
import { buildRuleICS, ICSPredicateFields } from "./firewall-ics-fields";
import { icsDraftFrom } from "./firewall-rule-forms";

function input(protocol: string, addresses = "") {
  return {
    enabled: true, protocol, addresses, functionCodes: "", unitId: "", objectClasses: "",
    readOnly: false, writeOnly: false, mode: "learn" as const,
    iec: iec104DraftFrom(undefined), action: "DENY" as const,
  };
}

function fields(protocol: string, addresses: string) {
  const noop = () => {};
  return renderToStaticMarkup(createElement(ICSPredicateFields, {
    ...input(protocol, addresses), globalMode: "learn",
    onProtocolChange: noop, onModeChange: noop, onFunctionCodesChange: noop,
    onAddressesChange: noop, onUnitIdChange: noop, onObjectClassesChange: noop,
    onReadOnlyChange: noop, onWriteOnlyChange: noop, onIecChange: noop,
  }));
}

for (const protocol of ["dnp3", "cip"]) {
  test(`${protocol}: firewall editor refuses save/preview and shows existing filter for removal`, () => {
    assert.doesNotMatch(fields(protocol, ""), /Point indices|Station Addresses|Remove address filter/);
    assert.match(fields(protocol, "10-20"), /Existing address filter:.*10-20/);
    assert.ok(fields(protocol, "10-20").includes(UNSUPPORTED_ADDRESSES));
    assert.deepEqual(buildRuleICS(input(protocol, "10-20")), { ok: false, error: UNSUPPORTED_ADDRESSES });
    const repaired = buildRuleICS({ ...input(protocol), existing: { protocol, addresses: ["10-20"] } });
    assert.equal(repaired.ok, true);
    if (repaired.ok) assert.deepEqual(repaired.ics?.addresses, []);
  });

  test(`${protocol}: new firewall draft carries no example address when switching protocol`, () => {
    const draft = icsDraftFrom(undefined, "learn");
    assert.equal(draft.addresses, "");
    const built = buildRuleICS({ ...draft, enabled: true, protocol, action: "ALLOW" });
    assert.equal(built.ok, true);
    if (built.ok) assert.equal(built.ics?.addresses, undefined);
    assert.equal(icsDraftFrom({ protocol, addresses: ["10-20"] }, "learn").addresses, "10-20");
    assert.equal(icsDraftFrom({ protocol, addresses: [""] }, "learn").addresses, '[""]');
  });
}

test("firewall editor keeps Modbus address input and IEC104 ca/ioa", () => {
  assert.match(fields("modbus", "10-20"), /Register \/ coil addresses/);
  const modbus = buildRuleICS(input("modbus", "0x0100-511"));
  if (!modbus.ok) assert.fail(modbus.error);
  assert.deepEqual(modbus.ics?.addresses, ["0x0100-511"]);
  const iec = buildRuleICS({ ...input("iec104"), iec: { ...iec104DraftFrom(undefined), ca: "1", ioa: "100-101" } });
  if (!iec.ok) assert.fail(iec.error);
  assert.deepEqual(iec.ics?.ca, [1]);
  assert.deepEqual(iec.ics?.ioa, [{ start: 100, end: 101 }]);
});
