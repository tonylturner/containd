/** Client-side validation helpers for network inputs. */

const ipv4Re = /^(\d{1,3}\.){3}\d{1,3}$/;
const ipv6Re = /^[0-9a-fA-F:]+$/;

/** Returns true if s looks like a valid IPv4 address. */
export function isIPv4(s: string): boolean {
  if (!ipv4Re.test(s)) return false;
  return s.split(".").every((o) => {
    const n = Number(o);
    return n >= 0 && n <= 255;
  });
}

/** Returns true if s looks like a valid IPv6 address (loose check). */
export function isIPv6(s: string): boolean {
  return ipv6Re.test(s) && s.includes(":");
}

/** Returns true if s is a valid IP address (v4 or v6). */
export function isIP(s: string): boolean {
  return isIPv4(s) || isIPv6(s);
}

/** Returns true if s is a valid CIDR notation (e.g. 192.168.1.0/24). */
export function isCIDR(s: string): boolean {
  const slash = s.lastIndexOf("/");
  if (slash < 0) return false;
  const ip = s.slice(0, slash);
  const prefix = Number(s.slice(slash + 1));
  if (!isIP(ip) || !Number.isInteger(prefix) || prefix < 0) return false;
  return isIPv4(ip) ? prefix <= 32 : prefix <= 128;
}

/** Returns true if s is a valid IP or CIDR. */
export function isIPOrCIDR(s: string): boolean {
  return isIP(s) || isCIDR(s);
}

/**
 * Validates a comma-separated list of CIDR addresses.
 * Returns null if valid, or an error message if invalid.
 */
export function validateCIDRList(input: string): string | null {
  const items = input
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (items.length === 0) return null; // empty is OK
  for (const item of items) {
    if (!isCIDR(item)) {
      return `"${item}" is not a valid CIDR (e.g. 192.168.1.0/24)`;
    }
  }
  return null;
}

/**
 * Validates a comma-separated list of IP addresses or CIDRs.
 * Returns null if valid, or an error message if invalid.
 */
export function validateIPOrCIDRList(input: string): string | null {
  const items = input
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (items.length === 0) return null;
  for (const item of items) {
    if (!isIPOrCIDR(item)) {
      return `"${item}" is not a valid IP or CIDR`;
    }
  }
  return null;
}

/** Validates a single IP address. Returns null if valid or empty. */
export function validateIP(input: string): string | null {
  const s = input.trim();
  if (!s) return null;
  if (!isIP(s)) return `"${s}" is not a valid IP address`;
  return null;
}

/** Validates a port number (1-65535). Returns null if valid or empty. */
export function validatePort(input: string): string | null {
  const s = input.trim();
  if (!s) return null;
  const n = Number(s);
  if (!Number.isInteger(n) || n < 1 || n > 65535) {
    return `"${s}" is not a valid port (1-65535)`;
  }
  return null;
}

/** Validates a port number or port range like "1000-2000". Returns null if valid or empty. */
export function validatePortOrRange(input: string): string | null {
  const s = input.trim();
  if (!s) return null;
  const dash = s.indexOf("-");
  if (dash < 0) return validatePort(s);
  const lo = Number(s.slice(0, dash));
  const hi = Number(s.slice(dash + 1));
  if (!Number.isInteger(lo) || !Number.isInteger(hi) || lo < 1 || hi > 65535 || lo > hi) {
    return `"${s}" is not a valid port or range (e.g. 80 or 1000-2000)`;
  }
  return null;
}
