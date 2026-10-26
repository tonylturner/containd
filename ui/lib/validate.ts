/** Client-side validation helpers for network inputs. */

// Octets without leading zeros: the server's net.ParseIP refuses "010.0.0.1".
const ipv4Re = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const ipv6Re = /^[0-9a-fA-F:]+$/;

/** Returns true if s looks like a valid IPv4 address. */
export function isIPv4(s: string): boolean {
  return ipv4Re.test(s);
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

/** Validates a single IPv4 address. Returns null if valid or empty. */
export function validateIPv4(input: string): string | null {
  const s = input.trim();
  if (!s) return null;
  if (!isIPv4(s)) return `"${s}" is not a valid IPv4 address`;
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

/** Most labels one identity binding may carry. */
export const MAX_BINDING_IDENTITIES = 16;

const MAX_IDENTITY_LABEL_BYTES = 64;

/**
 * Validates one identity label as the server does: 1 to 64 bytes of
 * printable characters without surrounding spaces. Returns null if valid.
 */
export function validateIdentityLabel(label: string): string | null {
  const bytes = new TextEncoder().encode(label).length;
  if (bytes === 0 || bytes > MAX_IDENTITY_LABEL_BYTES) {
    return `identity "${label}" must be 1 to ${MAX_IDENTITY_LABEL_BYTES} bytes`;
  }
  if (label.trim() !== label) return `identity "${label}" has surrounding spaces`;
  // Go's unicode.IsPrint: letters, marks, numbers, punctuation, symbols and
  // the ASCII space.
  if (!/^[\p{L}\p{M}\p{N}\p{P}\p{S} ]*$/u.test(label)) {
    return `identity "${label}" has a non-printable character`;
  }
  return null;
}

/**
 * Parses comma-separated identity labels into distinct, valid labels.
 * Commas separate labels, so a label cannot contain one.
 */
export function parseIdentityLabels(
  input: string,
): { ok: true; labels: string[] } | { ok: false; error: string } {
  const labels: string[] = [];
  for (const item of input.split(",").map((s) => s.trim()).filter(Boolean)) {
    const err = validateIdentityLabel(item);
    if (err) return { ok: false, error: err };
    if (labels.includes(item)) return { ok: false, error: `identity "${item}" is listed twice` };
    labels.push(item);
  }
  return { ok: true, labels };
}

/**
 * Longest zone name in bytes: enforcement names each zone's interface set
 * zone_<hex name>, and nftables names are at most 255 bytes. Equals the
 * engine's MaxZoneNameBytes; pkg/dp/enforce/zones_limit_test.go fails when
 * they differ.
 */
export const MAX_ZONE_NAME_BYTES = 125;

/** Zone names are identifiers: the API path /zones/{name} and the CLI take them bare. */
const ZONE_NAME_RE = /^[a-zA-Z0-9_-]+$/;

/**
 * Validates a zone name. The server refuses a blank name, leading or
 * trailing whitespace, and more than MAX_ZONE_NAME_BYTES of UTF-8; the UI
 * also keeps names to letters, digits, dash and underscore, because a name
 * with '/' cannot be updated or deleted through /zones/{name} and other
 * characters hurt the CLI. Returns null if valid.
 */
export function validateZoneName(name: string): string | null {
  if (name.trim() === "") return "Zone name is required.";
  if (name.trim() !== name) return "Zone name cannot start or end with a space.";
  if (!ZONE_NAME_RE.test(name)) return "Only letters, numbers, dash, and underscore allowed (no spaces).";
  const bytes = new TextEncoder().encode(name).length;
  if (bytes > MAX_ZONE_NAME_BYTES) {
    return `Zone name is ${bytes} bytes; the limit is ${MAX_ZONE_NAME_BYTES} bytes.`;
  }
  return null;
}
