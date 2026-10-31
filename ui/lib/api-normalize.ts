import type {
  FirewallRule,
  ICSPredicate,
  IEC104Class,
  IOARange,
  Protocol,
  RateLimit,
  RuleAction,
  RuleSchedule,
} from "./api-firewall";

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

function toIntegerList(value: unknown): number[] {
  return toNumberList(value).filter((item) => Number.isInteger(item));
}

const IEC104_CLASSES: ReadonlySet<string> = new Set<IEC104Class>([
  "monitor",
  "control",
  "system",
  "unknown",
]);

function toIEC104Classes(value: unknown): IEC104Class[] {
  return toStringList(value).filter((item): item is IEC104Class =>
    IEC104_CLASSES.has(item),
  );
}

function toIOARanges(value: unknown): IOARange[] {
  return asList(value).flatMap((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) return [];
    const { start, end } = item as Record<string, unknown>;
    return typeof start === "number" &&
      typeof end === "number" &&
      Number.isInteger(start) &&
      Number.isInteger(end)
      ? [{ start, end }]
      : [];
  });
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
    direction:
      record.direction === "request" || record.direction === "response"
        ? record.direction
        : undefined,
    mode:
      record.mode === "enforce" || record.mode === "monitor"
        ? record.mode
        : undefined,
    typeIds: toIntegerList(record.typeIds),
    classes: toIEC104Classes(record.classes),
    ca: toIntegerList(record.ca),
    ioa: toIOARanges(record.ioa),
  };

  if (typeof record.unitId === "number" && Number.isFinite(record.unitId)) {
    normalized.unitId = Math.trunc(record.unitId);
  } else if (typeof record.unitId === "string" && record.unitId.trim() !== "") {
    const parsed = Number(record.unitId.trim());
    if (Number.isFinite(parsed)) normalized.unitId = Math.trunc(parsed);
  }

  // Booleans keep their wire presence: the server omits false values, and an
  // invented `writeOnly: false` is a forbidden key for some protocols.
  if (typeof record.readOnly === "boolean") normalized.readOnly = record.readOnly;
  if (typeof record.writeOnly === "boolean") normalized.writeOnly = record.writeOnly;

  if ((normalized.functionCode?.length ?? 0) === 0) delete normalized.functionCode;
  if ((normalized.addresses?.length ?? 0) === 0) delete normalized.addresses;
  if ((normalized.objectClasses?.length ?? 0) === 0) delete normalized.objectClasses;
  if ((normalized.typeIds?.length ?? 0) === 0) delete normalized.typeIds;
  if ((normalized.classes?.length ?? 0) === 0) delete normalized.classes;
  if ((normalized.ca?.length ?? 0) === 0) delete normalized.ca;
  if ((normalized.ioa?.length ?? 0) === 0) delete normalized.ioa;
  if (!normalized.direction) delete normalized.direction;
  if (!normalized.mode) delete normalized.mode;
  if (normalized.unitId == null) delete normalized.unitId;
  if (!normalized.protocol) delete normalized.protocol;

  for (const key of ["cot", "originators", "commandStates", "commandQualifiers", "masters", "outstations", "groups", "variations", "instances", "attributes"] as const) {
    if (record[key] !== undefined) normalized[key] = toIntegerList(record[key]);
  }
  if (record.tags !== undefined) normalized.tags = toStringList(record.tags);
  for (const key of ["negative", "test"] as const) {
    const value = record[key];
    if (typeof value === "boolean") normalized[key] = value;
  }
  if (record.selectExecute === "select" || record.selectExecute === "execute") normalized.selectExecute = record.selectExecute;

  // `ics: {}` is a valid L3/L4-only predicate; keep it an object.
  return normalized;
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
    action: normalizeRuleAction(record.action),
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
  const rateLimit = normalizeRateLimit(record.rateLimit);
  if (rateLimit) normalized.rateLimit = rateLimit;
  if (typeof record.tag === "string" && record.tag !== "") normalized.tag = record.tag;
  const identities = toStringList(record.identities);
  if (identities.length > 0) normalized.identities = identities;
  const schedule = normalizeSchedule(record.schedule);
  if (schedule) normalized.schedule = schedule;

  if ((normalized.sourceZones?.length ?? 0) === 0) delete normalized.sourceZones;
  if ((normalized.destZones?.length ?? 0) === 0) delete normalized.destZones;
  if ((normalized.sources?.length ?? 0) === 0) delete normalized.sources;
  if ((normalized.destinations?.length ?? 0) === 0) delete normalized.destinations;
  if ((normalized.protocols?.length ?? 0) === 0) delete normalized.protocols;
  if (!normalized.ics) delete normalized.ics;

  return normalized;
}

const RULE_ACTIONS: ReadonlySet<string> = new Set<RuleAction>([
  "ALLOW",
  "DENY",
  "RESET",
  "RATE_LIMIT",
  "TAG",
]);

// The server rejects any other action, so an unknown value is a malformed
// response; DENY is the conservative reading.
export function normalizeRuleAction(value: unknown): RuleAction {
  return typeof value === "string" && RULE_ACTIONS.has(value)
    ? (value as RuleAction)
    : "DENY";
}

function normalizeRateLimit(value: unknown): RateLimit | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const { packetsPerSecond, burst } = value as Record<string, unknown>;
  if (typeof packetsPerSecond !== "number" || !Number.isInteger(packetsPerSecond)) {
    return undefined;
  }
  const rateLimit: RateLimit = { packetsPerSecond };
  if (typeof burst === "number" && Number.isInteger(burst) && burst > 0) {
    rateLimit.burst = burst;
  }
  return rateLimit;
}

function normalizeSchedule(value: unknown): RuleSchedule | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  const schedule: RuleSchedule = {};
  const days = toStringList(record.daysOfWeek);
  if (days.length > 0) schedule.daysOfWeek = days;
  for (const key of ["startTime", "endTime", "timezone"] as const) {
    const v = record[key];
    if (typeof v === "string" && v !== "") schedule[key] = v;
  }
  return Object.keys(schedule).length > 0 ? schedule : undefined;
}

export function normalizeFirewallRules(value: unknown): FirewallRule[] {
  return asList(value).map(normalizeFirewallRule);
}
