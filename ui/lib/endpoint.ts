/**
 * An event or flow endpoint for display. The address alone when the port is
 * absent or zero, as for ICMP; address:port otherwise, with an IPv6 address
 * in brackets ([2001:db8::1]:502). "—" when there is no address. Syslog
 * formats event endpoints the same way.
 */
export function formatEndpoint(ip: string | undefined, port: number | undefined): string {
  if (!ip) return "—";
  if (!port) return ip;
  return `${ip.includes(":") ? `[${ip}]` : ip}:${port}`;
}
