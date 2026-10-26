import { expect, test } from "@playwright/test";

import { firstHostInCIDR, pickWanCIDR } from "../app/firewall/firewall-utils";
import type { InterfaceState } from "../lib/api";

// The firewall quick start infers the WAN gateway as the first host of the
// WAN interface's IPv4 address. It reads only addresses that isCIDR and isIPv4
// accept, so a malformed address never turns into a gateway.

test("firstHostInCIDR returns the address after the network address", () => {
  expect(firstHostInCIDR("192.0.2.7/24")).toBe("192.0.2.1");
  expect(firstHostInCIDR("10.20.30.40/8")).toBe("10.0.0.1");
  expect(firstHostInCIDR("172.16.5.9/0")).toBe("0.0.0.1");
});

test("firstHostInCIDR refuses what isCIDR or isIPv4 refuses", () => {
  for (const cidr of [
    "010.0.0.1/24",
    "0x1.0.0.1/24",
    "1e1.0.0.1/24",
    "1.2.3/24",
    "1.2.3.4.5/24",
    "1.2.3.4/",
    "1.2.3.4/024",
    "1.2.3.4/33",
    "1.2.3.4/ 24",
    " 1.2.3.4/24",
    "1.2.3.4",
    "2001:db8::1/64",
  ]) {
    expect(firstHostInCIDR(cidr), cidr).toBeNull();
  }
});

test("pickWanCIDR picks the first IPv4 CIDR that is not link-local", () => {
  const state = (addrs: string[]): InterfaceState => ({ name: "eth1", index: 2, up: true, mtu: 1500, mac: "02:00:00:00:00:01", addrs });
  expect(pickWanCIDR(state(["fe80::1/64", "169.254.3.4/16", "010.0.0.5/24", "192.0.2.7/24"]))).toBe("192.0.2.7/24");
  expect(pickWanCIDR(state(["1.2.3.4/", "2001:db8::1/64"]))).toBeNull();
  expect(pickWanCIDR(null)).toBeNull();
});
