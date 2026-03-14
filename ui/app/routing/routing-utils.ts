import type { Interface, InterfaceState } from "../../lib/api";

export function normCIDR(s: string) {
  return s.trim();
}

export function ip4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map((p) => Number(p));
  if (nums.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return null;
  return ((nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]) >>> 0;
}

export function intToIP4(n: number): string {
  const v = n >>> 0;
  return `${(v >>> 24) & 255}.${(v >>> 16) & 255}.${(v >>> 8) & 255}.${v & 255}`;
}

export function maskFromPrefix(prefix: number): number | null {
  if (!Number.isFinite(prefix) || prefix < 0 || prefix > 32) return null;
  if (prefix === 0) return 0;
  return (0xffffffff << (32 - prefix)) >>> 0;
}

export function firstHostInCIDR(cidr: string): string | null {
  const raw = cidr.trim();
  const slash = raw.lastIndexOf("/");
  if (slash <= 0) return null;
  const ip = raw.slice(0, slash);
  const pfx = Number(raw.slice(slash + 1));
  const ipInt = ip4ToInt(ip);
  const mask = maskFromPrefix(pfx);
  if (ipInt == null || mask == null) return null;
  const net = ipInt & mask;
  const first = (net + 1) >>> 0;
  return intToIP4(first);
}

export function pickWanIface(ifs: Interface[]): Interface | null {
  const byName = ifs.find((i) => i.name === "wan");
  if (byName) return byName;
  const byZone = ifs.find((i) => (i.zone || "").toLowerCase() === "wan");
  return byZone ?? null;
}

export function effectiveDev(i: Interface | null): string {
  if (!i) return "";
  return (i.device || i.name || "").trim();
}

export function pickWanCIDR(state: InterfaceState | null): string | null {
  if (!state) return null;
  for (const addr of state.addrs || []) {
    const s = String(addr);
    if (!s.includes("/")) continue;
    if (s.includes(":")) continue;
    if (s.startsWith("169.254.")) continue;
    return s;
  }
  return null;
}
