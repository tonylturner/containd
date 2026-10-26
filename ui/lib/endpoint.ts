/**
 * An event, flow or forward endpoint for display. The address alone when the
 * port is absent, zero or not a number, as for ICMP; address:port otherwise,
 * with an IPv6 address in brackets ([2001:db8::1]:502). "—" when there is no
 * address. Ports arrive as numbers or, from conntrack and form inputs, as
 * decimal strings. Syslog formats event endpoints the same way.
 */
export function formatEndpoint(ip: string | undefined, port: number | string | undefined): string {
  if (!ip) return "—";
  const value = Number(port);
  if (!value) return ip;
  return `${ip.includes(":") ? `[${ip}]` : ip}:${value}`;
}
