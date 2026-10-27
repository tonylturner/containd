import assert from "node:assert/strict";
import { test } from "node:test";
import { createElement, type ReactNode } from "react";

const { renderToStaticMarkup } = require("react-dom/server") as {
  renderToStaticMarkup: (node: ReactNode) => string;
};

import { ICSAddressFields } from "./ics-address-fields";
import { EditICSModal } from "./ics-edit-modal";
import { addressFilterError, buildICSRuleUpdate, icsAddressDraftFrom, PROTOCOLS, UNSUPPORTED_ADDRESSES } from "./ics-shared";

for (const protocol of ["dnp3", "cip"]) {
  test(`${protocol}: ICS editor offers no new address input`, () => {
    const html = renderToStaticMarkup(createElement(EditICSModal, {
      rule: { id: "r1", action: "DENY", ics: { protocol } },
      onClose() {},
      onSave() {},
    }));
    assert.doesNotMatch(html, /Register \/ coil addresses|Station addresses|CIP path \(hex string\)|Remove address filter/);
    assert.equal(renderToStaticMarkup(createElement(ICSAddressFields, { protocol, addresses: "", onChange() {} })), "");
    assert.equal(PROTOCOLS[protocol].addrHelp, UNSUPPORTED_ADDRESSES);
  });

  test(`${protocol}: existing filter and cause remain visible until explicit removal`, () => {
    const html = renderToStaticMarkup(createElement(EditICSModal, {
      rule: { id: "r1", action: "DENY", ics: { protocol, addresses: ["10-20", "30"] } },
      onClose() {},
      onSave() {},
    }));
    assert.match(html, /Existing address filter:.*10-20, 30/);
    assert.ok(html.includes(UNSUPPORTED_ADDRESSES));
    assert.match(html, /Remove address filter/);
    assert.equal(addressFilterError(protocol, "10-20"), UNSUPPORTED_ADDRESSES);
    assert.equal(addressFilterError(protocol, ""), null);
    for (const addresses of [[""], ["   "]]) {
      const draft = icsAddressDraftFrom({ protocol, addresses });
      assert.ok(draft.includes(JSON.stringify(addresses)));
      assert.equal(addressFilterError(protocol, draft), UNSUPPORTED_ADDRESSES);
    }

    let changed: string | undefined;
    const fields = ICSAddressFields({ protocol, addresses: "10-20", onChange: (v) => { changed = v; } });
    const button = fields?.props.children.find((child: { type: string }) => child.type === "button");
    assert.ok(button);
    button.props.onClick();
    assert.equal(changed, "");

    const corrected = buildICSRuleUpdate(protocol, "", "", "", "", false, false, "", { protocol, addresses: ["10-20"] });
    assert.deepEqual(corrected.addresses, []); // PATCH must clear, not omit.
  });
}

test("Modbus retains decimal/hex ranges without an unsupported-filter error", () => {
  const html = renderToStaticMarkup(createElement(ICSAddressFields, {
    protocol: "modbus", addresses: "0x0100-511", onChange() {},
  }));
  assert.match(html, /Register \/ coil addresses/);
  assert.match(html, /value="0x0100-511"/);
  assert.equal(addressFilterError("modbus", "0x0100-511"), null);
  assert.deepEqual(buildICSRuleUpdate("modbus", "3", "0x0100-511", "1", "", false, false, "learn").addresses, ["0x0100-511"]);
});
