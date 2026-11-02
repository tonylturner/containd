import type { DHCPConfig, DHCPPool, DHCPReservation, Interface } from "../../lib/api";

function ipv4(value: string): number | null {
  const parts = value.trim().split(".");
  if (parts.length !== 4 || parts.some(p => !/^(0|[1-9]\d{0,2})$/.test(p) || Number(p) > 255)) return null;
  return parts.reduce((n, p) => n * 256 + Number(p), 0);
}

export function validateRows(cfg: DHCPConfig): string | null {
  for (const [i, pool] of (cfg.pools ?? []).entries()) {
    const start = ipv4(pool.start), end = ipv4(pool.end);
    if (!pool.iface.trim() || start === null || end === null || start > end) {
      return `Pool ${i + 1}: choose an interface and valid IPv4 start/end addresses in ascending order.`;
    }
  }
  const seen = new Set<string>();
  for (const [i, row] of (cfg.reservations ?? []).entries()) {
    const mac = row.mac.trim();
    const bytes = mac.split(/[:-]/);
    const dotted = mac.split(".");
    const validMAC = ([6, 8, 20].includes(bytes.length) && bytes.every(p => /^[\da-f]{2}$/i.test(p)) && !(mac.includes(":") && mac.includes("-"))) ||
      ([3, 4, 10].includes(dotted.length) && dotted.every(p => /^[\da-f]{4}$/i.test(p)));
    const ip = ipv4(row.ip);
    if (!row.iface.trim() || !validMAC || ip === null) return `Reservation ${i + 1}: choose an interface and enter a valid MAC and IPv4 address.`;
    const key = `${row.iface.trim()}|${mac.toLowerCase()}`;
    if (seen.has(key)) return `Reservation ${i + 1}: duplicate MAC on this interface.`;
    seen.add(key);
    const pools = (cfg.pools ?? []).filter(p => p.iface === row.iface);
    if (pools.length && !pools.some(p => ip >= ipv4(p.start)! && ip <= ipv4(p.end)!)) {
      return `Reservation ${i + 1}: IP must fall inside a pool for its interface.`;
    }
  }
  return null;
}

export function InterfacePicker({ value, interfaces, disabled, label, onChange }: {
  value: string; interfaces: Interface[]; disabled: boolean; label: string; onChange: (value: string) => void;
}) {
  return (
    <label className="block min-w-0 text-xs">
      {label}
      <select className="mt-1 w-full input-industrial" value={value} disabled={disabled} onChange={e => onChange(e.target.value)}>
        <option value="">Choose interface</option>
        {value && !interfaces.some(i => i.name === value) && <option value={value}>{value} (not in configured interfaces)</option>}
        {interfaces.map(i => <option key={i.name} value={i.name}>{i.alias ? `${i.alias} (${i.name})` : i.name}</option>)}
      </select>
    </label>
  );
}

export function DHCPRows({ pools, reservations, interfaces, disabled, onPools, onReservations }: {
  pools: DHCPPool[]; reservations?: never; interfaces: Interface[]; disabled: boolean;
  onPools: (rows: DHCPPool[]) => void; onReservations?: never;
} | {
  reservations: DHCPReservation[]; pools?: never; interfaces: Interface[]; disabled: boolean;
  onReservations: (rows: DHCPReservation[]) => void; onPools?: never;
}) {
  const rows = pools ?? reservations;
  const title = pools ? "Pool" : "Reservation";
  function change(index: number, field: string, value: string) {
    if (pools) onPools(pools.map((r, i) => i === index ? { ...r, [field]: value } : r));
    else onReservations(reservations.map((r, i) => i === index ? { ...r, [field]: value } : r));
  }
  return (
    <section className="min-w-0 space-y-3" aria-label={`${title}s`}>
      <h3 className="text-sm font-semibold">{title}s</h3>
      {!pools && <p className="text-xs text-(--text-muted)">Reservations pin a MAC to an IP on an interface. Hostnames are reported in leases, not configurable reservations.</p>}
      {rows.map((row, index) => (
        <fieldset key={index} disabled={disabled} className="min-w-0 rounded-xs border p-3">
          <legend className="px-1 text-xs">{title} {index + 1}</legend>
          <div className="grid min-w-0 gap-3 md:grid-cols-3">
            <InterfacePicker value={row.iface} interfaces={interfaces} disabled={disabled} label={`${title} ${index + 1} interface`} onChange={v => change(index, "iface", v)} />
            {(pools ? ["start", "end"] : ["mac", "ip"]).map(field => (
              <label key={field} className="min-w-0 text-xs">
                {title} {index + 1} {field === "mac" ? "MAC" : field === "ip" ? "IP" : field}
                <input className="mt-1 w-full input-industrial" value={"start" in row ? row[field as keyof DHCPPool] : row[field as keyof DHCPReservation]}
                  onChange={e => change(index, field, e.target.value)} />
              </label>
            ))}
          </div>
          <button type="button" className="mt-3 rounded-xs border px-3 py-1 text-xs" onClick={() => {
            if (pools) onPools(pools.filter((_, i) => i !== index));
            else onReservations(reservations.filter((_, i) => i !== index));
          }}>Remove {title.toLowerCase()}</button>
        </fieldset>
      ))}
      <button disabled={disabled} type="button" className="rounded-xs border px-3 py-2 text-sm" onClick={() => {
        if (pools) onPools([...pools, { iface: "", start: "", end: "" }]);
        else onReservations([...reservations, { iface: "", mac: "", ip: "" }]);
      }}>Add {title.toLowerCase()}</button>
    </section>
  );
}
