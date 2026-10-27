import type { ScanExclude, ScanInclude, ScanSelection } from "../../../../lib/api";

/**
 * Destination ports the engine's ICS decoders own by default. The server
 * refuses a scan include that covers one; this list only flags the conflict
 * before the save, the server's reply is authoritative.
 */
export const ICS_DECODER_PORTS: Record<number, string> = {
  502: "Modbus",
  2222: "EtherNet/IP",
  2404: "IEC 104",
  20000: "DNP3",
  44818: "EtherNet/IP",
};

/** A decimal port or an inclusive N-M range, both from 1 to 65535. */
export function parsePortSpec(spec: string): { lo: number; hi: number } | null {
  const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(spec.trim());
  if (!m) return null;
  const lo = Number(m[1]);
  const hi = m[2] === undefined ? lo : Number(m[2]);
  if (lo < 1 || hi > 65535 || hi < lo) return null;
  return { lo, hi };
}

/** The first ICS decoder port an include's port list covers, as a message, or null. */
export function icsPortConflict(ports: string[]): string | null {
  for (const spec of listEntries(ports)) {
    const range = parsePortSpec(spec);
    if (!range) continue;
    for (const [port, protocol] of Object.entries(ICS_DECODER_PORTS)) {
      const p = Number(port);
      if (p >= range.lo && p <= range.hi) {
        return `${spec} covers ICS decoder port ${p} (${protocol}); the server refuses it.`;
      }
    }
  }
  return null;
}

/**
 * A comma-separated field is kept as its raw pieces while editing so the
 * input round-trips every keystroke; entries are trimmed and empties dropped
 * when the selection is saved.
 */
export function splitList(text: string): string[] {
  return text.split(",");
}

export function joinList(entries: string[] | undefined): string {
  return (entries ?? []).join(",");
}

/** The trimmed, non-empty entries of a list field. */
export function listEntries(entries: string[] | undefined): string[] {
  return (entries ?? []).map((e) => e.trim()).filter(Boolean);
}

function listOrUndefined(entries: string[] | undefined): string[] | undefined {
  const cleaned = listEntries(entries);
  return cleaned.length ? cleaned : undefined;
}

/** An exclude entry with no field set, which the server rejects. */
export function excludeIsEmpty(entry: ScanExclude): boolean {
  return [entry.sourceZones, entry.destZones, entry.sources, entry.destinations, entry.destPorts]
    .every((list) => listEntries(list).length === 0);
}

/** The selection as the server stores it: trimmed lists, empty lists omitted. */
export function normalizeScan(scan: ScanSelection | undefined): ScanSelection {
  const include = (scan?.include ?? []).map((entry: ScanInclude): ScanInclude => ({
    sourceZones: listOrUndefined(entry.sourceZones),
    destZones: listOrUndefined(entry.destZones),
    destPorts: listEntries(entry.destPorts),
  }));
  const exclude = (scan?.exclude ?? []).map((entry: ScanExclude): ScanExclude => ({
    sourceZones: listOrUndefined(entry.sourceZones),
    destZones: listOrUndefined(entry.destZones),
    sources: listOrUndefined(entry.sources),
    destinations: listOrUndefined(entry.destinations),
    destPorts: listOrUndefined(entry.destPorts),
  }));
  return {
    include: include.length ? include : undefined,
    exclude: exclude.length ? exclude : undefined,
    downloadMode: scan?.downloadMode ?? "hold",
    icsZones: listOrUndefined(scan?.icsZones),
    icsAssets: listOrUndefined(scan?.icsAssets),
  };
}
