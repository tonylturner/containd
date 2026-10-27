import type { Zone } from "./api";

/** A zone for display: "alias (name)" when it has an alias, else its name. */
export function zoneLabel(zone: Zone): string {
  return zone.alias ? `${zone.alias} (${zone.name})` : zone.name;
}

/** The display label of the named zone, or the bare name when it is unknown. */
export function zoneName(zones: Zone[], name: string): string {
  const match = zones.find((z) => z.name === name);
  return match ? zoneLabel(match) : name;
}
