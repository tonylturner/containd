import type {
  FirewallRule,
  ICSPredicate,
  IEC104Class,
  IOARange,
} from "../../lib/api";
import type { ICSMode, ICSModeSelection } from "./ics-shared";

// IEC 60870-5-104 rule model for the editors.
// The client-side checks mirror the server validation ranges so operators see
// mistakes before saving; the server stays authoritative and runs full validation.

export const IEC104_PORT = "2404";
export const IEC104_CLASSES: IEC104Class[] = [
  "monitor",
  "control",
  "system",
  "unknown",
];

const TYPE_ID_MIN = 1;
const TYPE_ID_MAX = 255;
const CA_MAX = 65534;
const CA_BROADCAST = 65535;
const IOA_MAX = 16777215;

export type IEC104TypeInfo = {
  name: string;
  cls: IEC104Class;
  /** True when containd decodes the type. */
  descriptor: boolean;
};

/** Supported decoder Type IDs. Every other Type ID is class `unknown`. */
export const IEC104_TYPES: Record<number, IEC104TypeInfo> = {
  1: { name: "M_SP_NA_1 single point", cls: "monitor", descriptor: true },
  3: { name: "M_DP_NA_1 double point", cls: "monitor", descriptor: true },
  13: { name: "M_ME_NC_1 short float", cls: "monitor", descriptor: true },
  30: { name: "M_SP_TB_1 single point, time", cls: "monitor", descriptor: true },
  31: { name: "M_DP_TB_1 double point, time", cls: "monitor", descriptor: true },
  45: { name: "C_SC_NA_1 single command", cls: "control", descriptor: true },
  46: { name: "C_DC_NA_1 double command", cls: "control", descriptor: true },
  47: { name: "C_RC_NA_1 regulating step", cls: "control", descriptor: true },
  48: { name: "C_SE_NA_1 setpoint normalized", cls: "control", descriptor: true },
  49: { name: "C_SE_NB_1 setpoint scaled", cls: "control", descriptor: true },
  50: { name: "C_SE_NC_1 setpoint float", cls: "control", descriptor: true },
  51: { name: "C_BO_NA_1 bitstring", cls: "control", descriptor: true },
  58: { name: "C_SC_TA_1 single command, time", cls: "control", descriptor: true },
  59: { name: "C_DC_TA_1 double command, time", cls: "control", descriptor: true },
  60: { name: "C_RC_TA_1 regulating step, time", cls: "control", descriptor: true },
  61: { name: "C_SE_TA_1 setpoint normalized, time", cls: "control", descriptor: true },
  62: { name: "C_SE_TB_1 setpoint scaled, time", cls: "control", descriptor: true },
  63: { name: "C_SE_TC_1 setpoint float, time", cls: "control", descriptor: true },
  64: { name: "C_BO_TA_1 bitstring, time", cls: "control", descriptor: true },
  70: { name: "M_EI_NA_1 end of initialization", cls: "system", descriptor: true },
  100: { name: "C_IC_NA_1 general interrogation", cls: "system", descriptor: true },
  101: { name: "C_CI_NA_1 counter interrogation", cls: "system", descriptor: true },
  102: { name: "C_RD_NA_1 read", cls: "system", descriptor: true },
  103: { name: "C_CS_NA_1 clock sync", cls: "system", descriptor: true },
  104: { name: "C_TS_NA_1 test (IEC 101 only)", cls: "unknown", descriptor: false },
  105: { name: "C_RP_NA_1 reset process", cls: "system", descriptor: true },
  106: { name: "C_CD_NA_1 delay acquisition (IEC 101 only)", cls: "unknown", descriptor: false },
  107: { name: "C_TS_TA_1 test with time", cls: "system", descriptor: true },
};

export function iec104TypeInfo(typeId: number): IEC104TypeInfo {
  return (
    IEC104_TYPES[typeId] ?? {
      name: "not decoded",
      cls: "unknown",
      descriptor: false,
    }
  );
}

/** Text form of the IEC fields, as the editors hold them. */
export type IEC104Draft = {
  typeIds: string;
  classes: IEC104Class[];
  ca: string;
  ioa: string;
  direction: "" | "request" | "response";
  readOnly: boolean;
};

export function formatIOARanges(ranges: IOARange[] | undefined): string {
  return (ranges ?? [])
    .map((r) => (r.start === r.end ? String(r.start) : `${r.start}-${r.end}`))
    .join(", ");
}

export function iec104DraftFrom(ics: ICSPredicate | undefined): IEC104Draft {
  const own = ics?.protocol === "iec104" ? ics : undefined;
  return {
    typeIds: (own?.typeIds ?? []).join(", "),
    classes: own?.classes ?? [],
    ca: (own?.ca ?? []).join(", "),
    ioa: formatIOARanges(own?.ioa),
    direction: own?.direction ?? "",
    readOnly: own?.readOnly ?? false,
  };
}

type Parsed<T> = { ok: true; value: T } | { ok: false; error: string };

function splitTokens(text: string): string[] {
  return text
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
}

function parseUint(token: string, what: string): Parsed<number> {
  if (!/^\d+$/.test(token)) {
    return { ok: false, error: `${what} "${token}" is not a whole number.` };
  }
  return { ok: true, value: Number(token) };
}

function dedupe(values: number[]): number[] {
  return Array.from(new Set(values));
}

/** Parses a Type ID list, 1..255. */
export function parseTypeIds(text: string): Parsed<number[]> {
  const out: number[] = [];
  for (const token of splitTokens(text)) {
    const n = parseUint(token, "Type ID");
    if (!n.ok) return n;
    if (n.value < TYPE_ID_MIN || n.value > TYPE_ID_MAX) {
      return { ok: false, error: `Type ID ${n.value} is outside 1-255.` };
    }
    out.push(n.value);
  }
  return { ok: true, value: dedupe(out) };
}

/** Parses a common address (CA) list, 0..65534. 65535 is broadcast. */
export function parseCAs(text: string): Parsed<number[]> {
  const out: number[] = [];
  for (const token of splitTokens(text)) {
    const n = parseUint(token, "CA");
    if (!n.ok) return n;
    if (n.value === CA_BROADCAST) {
      return {
        ok: false,
        error: "CA 65535 is the broadcast address; rules cannot name it.",
      };
    }
    if (n.value > CA_MAX) {
      return { ok: false, error: `CA ${n.value} is outside 0-65534.` };
    }
    out.push(n.value);
  }
  return { ok: true, value: dedupe(out) };
}

/** Parses closed IOA ranges ("2001, 65536-65567"), 0..16777215, no overlaps. */
export function parseIOARanges(text: string): Parsed<IOARange[]> {
  const out: IOARange[] = [];
  for (const token of splitTokens(text)) {
    const parts = token.split("-").map((p) => p.trim());
    if (parts.length > 2) {
      return { ok: false, error: `IOA range "${token}" is not start-end.` };
    }
    const start = parseUint(parts[0], "IOA");
    if (!start.ok) return start;
    const end = parts.length === 2 ? parseUint(parts[1], "IOA") : start;
    if (!end.ok) return end;
    if (start.value > IOA_MAX || end.value > IOA_MAX) {
      return { ok: false, error: `IOA range "${token}" is outside 0-16777215.` };
    }
    if (start.value > end.value) {
      return { ok: false, error: `IOA range "${token}" starts after it ends.` };
    }
    out.push({ start: start.value, end: end.value });
  }
  const sorted = [...out].sort((a, b) => a.start - b.start);
  for (let i = 1; i < sorted.length; i += 1) {
    if (sorted[i].start <= sorted[i - 1].end) {
      return {
        ok: false,
        error: `IOA ranges ${formatIOARanges([sorted[i - 1]])} and ${formatIOARanges([sorted[i]])} overlap.`,
      };
    }
  }
  return { ok: true, value: out };
}

export type IEC104BuildResult =
  | { ok: true; ics: ICSPredicate }
  | { ok: false; error: string };

/**
 * Builds the wire predicate. Only IEC104 keys are emitted: functionCode,
 * unitId, addresses, objectClasses and writeOnly are forbidden for iec104 by
 * presence, and an empty list is invalid, so absent fields are omitted.
 */
function buildIEC104Predicate(
  draft: IEC104Draft,
  mode: ICSModeSelection,
  action: FirewallRule["action"],
  globalMode?: ICSMode,
): IEC104BuildResult {
  const typeIds = parseTypeIds(draft.typeIds);
  if (!typeIds.ok) return typeIds;
  const ca = parseCAs(draft.ca);
  if (!ca.ok) return ca;
  const ioa = parseIOARanges(draft.ioa);
  if (!ioa.ok) return ioa;

  const effectiveMode = mode || globalMode || "learn";
  if (action === "ALLOW" && effectiveMode !== "learn") {
    const undecoded = typeIds.value.filter((t) => !iec104TypeInfo(t).descriptor);
    if (undecoded.length > 0) {
      return {
        ok: false,
        error: `Allow rules can name only Type IDs that containd decodes; ${undecoded.join(", ")} is not decoded. Use a deny or learn rule.`,
      };
    }
  }

  const ics: ICSPredicate = { protocol: "iec104" };
  if (typeIds.value.length > 0) ics.typeIds = typeIds.value;
  if (draft.classes.length > 0) {
    ics.classes = IEC104_CLASSES.filter((c) => draft.classes.includes(c));
  }
  if (draft.direction) ics.direction = draft.direction;
  if (ca.value.length > 0) ics.ca = ca.value;
  if (ioa.value.length > 0) ics.ioa = ioa.value;
  ics.readOnly = draft.readOnly;
  if (mode) ics.mode = mode;
  return { ok: true, ics };
}

const CLEARABLE_FIELDS = ["typeIds", "classes", "direction", "ca", "ioa"] as const;

/**
 * Builds the predicate for a rule save. `existing` is the stored predicate
 * when the save is an update. Rule updates are deep JSON merges
 * (api/http/firewall_rule_handlers.go mergeJSONObject), so a field left out
 * of the patch keeps its stored value. Strict server validation rejects null
 * on the IEC fields:
 * an update that would remove a stored IEC field is refused instead of
 * silently keeping the old filter.
 */
export function buildIEC104RuleICS(
  draft: IEC104Draft,
  mode: ICSModeSelection,
  action: FirewallRule["action"],
  existing?: ICSPredicate,
  globalMode?: ICSMode,
): IEC104BuildResult {
  const built = buildIEC104Predicate(draft, mode, action, globalMode);
  if (!built.ok || existing?.protocol !== "iec104") return built;
  const stuck = CLEARABLE_FIELDS.filter(
    (field) => existing[field] !== undefined && built.ics[field] === undefined,
  );
  if (stuck.length === 0) return built;
  return {
    ok: false,
    error: `Saving cannot clear ${stuck.join(", ")} on an existing rule because rule updates merge fields. Delete and recreate the rule to remove them.`,
  };
}

/** Short summaries for rule tables. */
export function summarizeIEC104(ics: ICSPredicate): {
  types: string;
  addresses: string;
} {
  const types = [
    (ics.typeIds ?? []).length > 0 ? `type ${(ics.typeIds ?? []).join(",")}` : "",
    (ics.classes ?? []).length > 0 ? (ics.classes ?? []).join("|") : "",
    ics.direction ?? "",
  ]
    .filter(Boolean)
    .join(" ");
  const addresses = [
    (ics.ca ?? []).length > 0 ? `CA ${(ics.ca ?? []).join(",")}` : "",
    (ics.ioa ?? []).length > 0 ? `IOA ${formatIOARanges(ics.ioa)}` : "",
  ]
    .filter(Boolean)
    .join(" ");
  return { types: types || "*", addresses: addresses || "*" };
}
