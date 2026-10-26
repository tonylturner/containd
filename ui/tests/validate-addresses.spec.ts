import { expect, test } from "@playwright/test";

import { isCIDR, isIPv6, validatePort } from "../lib/validate";

// The shared checks agree with the server's parsers. IPv6 verdicts are
// those of Go's netip.ParseAddr for addresses without a zone; prefix
// lengths are those of netip.ParsePrefix; ports are decimal digits only.

const ipv6Cases: [string, boolean][] = [
  ["::", true],
  ["::1", true],
  ["1::", true],
  ["0::0", true],
  ["2001:db8::5", true],
  ["2001:DB8::5", true],
  ["2001:0db8:0000:0000:0000:0000:0000:0001", true],
  ["1:2:3:4:5:6:7:8", true],
  ["1:2:3:4:5:6:7::", true],
  ["::2:3:4:5:6:7:8", true],
  ["::ffff:192.0.2.1", true],
  ["::192.0.2.1", true],
  ["1:2:3:4:5:6:192.0.2.1", true],
  ["1:2:3:4:5::192.0.2.1", true],
  ["1:2:3:4:5:6:7:8:9", false],
  ["1:2:3:4:5:6:7", false],
  ["1:2:3:4:5:6::7:8", false],
  ["1::2::3", false],
  [":::", false],
  [":1::", false],
  ["1::2:", false],
  [":1:2:3:4:5:6:7:8", false],
  ["1:2:3:4:5:6:7:8:", false],
  ["12345::", false],
  ["1:2:3:4:5:6:7:192.0.2.1", false],
  ["1:2:3:4:5:6::192.0.2.1", false],
  ["1:2:3:4:5:192.0.2.1", false],
  ["192.0.2.1::", false],
  ["::192.0.2.01", false],
  ["::ffff:192.0.2", false],
  ["::ffff:192.0.2.256", false],
  ["::ffff:1.2.3.4.5", false],
  ["::1.2.3.4:5", false],
  ["fe80::1%eth0", false],
  ["2001:db8::g", false],
  ["abcd", false],
  ["1.2.3.4", false],
  ["2001:db8::5 ", false],
  [" 2001:db8::5", false],
  ["", false],
];

test("isIPv6 accepts what netip.ParseAddr accepts", () => {
  for (const [s, ok] of ipv6Cases) {
    expect(isIPv6(s), JSON.stringify(s)).toBe(ok);
  }
});

test("isCIDR takes decimal prefix lengths within the address size", () => {
  const cases: [string, boolean][] = [
    ["10.0.0.0/24", true],
    ["10.0.0.0/0", true],
    ["10.0.0.0/32", true],
    ["2001:db8::/64", true],
    ["2001:db8::/128", true],
    ["::ffff:192.0.2.0/120", true],
    ["10.0.0.0/33", false],
    ["2001:db8::/129", false],
    ["10.0.0.0/", false],
    ["10.0.0.0/024", false],
    ["10.0.0.0/1e1", false],
    ["10.0.0.0/0x10", false],
    ["10.0.0.0/+8", false],
    ["10.0.0.0/ 8", false],
    ["2001:db8:::/64", false],
    ["fe80::/10%eth0", false],
  ];
  for (const [s, ok] of cases) {
    expect(isCIDR(s), JSON.stringify(s)).toBe(ok);
  }
});

test("validatePort accepts decimal digits from 1 to 65535 only", () => {
  for (const ok of ["1", "80", " 443 ", "65535", ""]) {
    expect(validatePort(ok), JSON.stringify(ok)).toBeNull();
  }
  for (const bad of ["0", "65536", "1.5", "1e3", "0x50", "+80", "-1", "80a", "8 0", "Infinity"]) {
    expect(validatePort(bad), JSON.stringify(bad)).toBe(`"${bad}" is not a valid port (1-65535)`);
  }
});
