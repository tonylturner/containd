import type { FirewallRule, ICSPredicate, Protocol } from "./api";

function asList(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (value == null) return [];
  if (typeof value === "object") {
    return Object.values(value as Record<string, unknown>);
  }
  return [value];
}

function toStringList(value: unknown): string[] {
  return asList(value)
    .map((item) =>
      typeof item === "string" ? item.trim() : String(item ?? "").trim(),
    )
    .filter(Boolean);
}

function toNumberList(value: unknown): number[] {
  return asList(value)
    .map((item) => {
      if (typeof item === "number") return item;
      if (typeof item === "string" && item.trim() !== "") {
        return Number(item.trim());
      }
      return Number.NaN;
    })
    .filter((item) => Number.isFinite(item));
}

function normalizeProtocol(value: unknown): Protocol | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const name =
    typeof record.name === "string" && record.name.trim() !== ""
      ? record.name.trim()
      : null;
  if (!name) return null;
  const protocol: Protocol = { name };
  if (typeof record.port === "string" && record.port.trim() !== "") {
    protocol.port = record.port.trim();
  } else if (typeof record.port === "number" && Number.isFinite(record.port)) {
    protocol.port = String(record.port);
  }
  return protocol;
}

function normalizeICSPredicate(value: unknown): ICSPredicate | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const record = value as Record<string, unknown>;
  const normalized: ICSPredicate = {
    protocol:
      typeof record.protocol === "string" && record.protocol.trim() !== ""
        ? record.protocol.trim()
        : undefined,
    functionCode: toNumberList(record.functionCode).map((item) =>
      Math.max(0, Math.trunc(item)),
    ),
    addresses: toStringList(record.addresses),
    objectClasses: toNumberList(record.objectClasses).map((item) =>
      Math.max(0, Math.trunc(item)),
    ),
    readOnly: record.readOnly === true,
    writeOnly: record.writeOnly === true,
    direction:
      record.direction === "request" || record.direction === "response"
        ? record.direction
        : undefined,
    mode:
      record.mode === "enforce" || record.mode === "learn"
        ? record.mode
        : undefined,
  };

  if (typeof record.unitId === "number" && Number.isFinite(record.unitId)) {
    normalized.unitId = Math.trunc(record.unitId);
  } else if (typeof record.unitId === "string" && record.unitId.trim() !== "") {
    const parsed = Number(record.unitId.trim());
    if (Number.isFinite(parsed)) normalized.unitId = Math.trunc(parsed);
  }

  if ((normalized.functionCode?.length ?? 0) === 0) delete normalized.functionCode;
  if ((normalized.addresses?.length ?? 0) === 0) delete normalized.addresses;
  if ((normalized.objectClasses?.length ?? 0) === 0) delete normalized.objectClasses;
  if (!normalized.direction) delete normalized.direction;
  if (!normalized.mode) delete normalized.mode;
  if (normalized.unitId == null) delete normalized.unitId;
  if (!normalized.protocol) delete normalized.protocol;

  return Object.keys(normalized).length > 0 ? normalized : undefined;
}

export function normalizeFirewallRule(value: unknown): FirewallRule {
  const record =
    value && typeof value === "object" && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : {};

  const normalized: FirewallRule = {
    id:
      typeof record.id === "string" && record.id.trim() !== ""
        ? record.id.trim()
        : "unknown-rule",
    action: record.action === "DENY" ? "DENY" : "ALLOW",
    sourceZones: toStringList(record.sourceZones),
    destZones: toStringList(record.destZones),
    sources: toStringList(record.sources),
    destinations: toStringList(record.destinations),
    protocols: asList(record.protocols)
      .map(normalizeProtocol)
      .filter((item): item is Protocol => item !== null),
    ics: normalizeICSPredicate(record.ics),
  };

  if (typeof record.description === "string" && record.description.trim() !== "") {
    normalized.description = record.description;
  }
  if (typeof record.log === "boolean") normalized.log = record.log;

  if ((normalized.sourceZones?.length ?? 0) === 0) delete normalized.sourceZones;
  if ((normalized.destZones?.length ?? 0) === 0) delete normalized.destZones;
  if ((normalized.sources?.length ?? 0) === 0) delete normalized.sources;
  if ((normalized.destinations?.length ?? 0) === 0) delete normalized.destinations;
  if ((normalized.protocols?.length ?? 0) === 0) delete normalized.protocols;
  if (!normalized.ics) delete normalized.ics;

  return normalized;
}

export function normalizeFirewallRules(value: unknown): FirewallRule[] {
  return asList(value).map(normalizeFirewallRule);
}
