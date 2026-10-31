import {
  deleteJSONResult,
  getJSONList,
  getJSONResult,
  patchJSONResult,
  postJSONResult,
} from "./api-request";
import {
  normalizeFirewallRule,
  normalizeFirewallRules,
  normalizeRuleAction,
} from "./api-normalize";
import { normalizeICSCoverageRule, type ICSCoverageRule } from "./api-ics-coverage";

import type { ApiResult, PortForward, TelemetryEvent } from "./api";

export type Protocol = {
  name: string;
  port?: string;
};

/** Effective predicate: omit a selector to match any value. */
export type ICSPredicate = {
  protocol?: string;
  functionCode?: number[];
  unitId?: number;
  addresses?: string[];
  objectClasses?: number[];
  readOnly?: boolean;
  writeOnly?: boolean;
  direction?: "request" | "response";
  /** Empty inherits the global mode, including in preview and PATCH bodies. */
  mode?: "enforce" | "monitor" | "";
  // IEC 60870-5-104 fields (protocol "iec104"). A missing field is a
  // wildcard; an empty list is a validation error, so never send [].
  typeIds?: number[];
  classes?: IEC104Class[];
  ca?: number[];
  ioa?: IOARange[];
  cot?: number[];
  originators?: number[];
  negative?: boolean;
  test?: boolean;
  selectExecute?: "select" | "execute";
  /** Types 45/58: SCS 0..1; types 46/47/59/60: DCS/RCS 1..2. */
  commandStates?: number[];
  /** QU bits 2..6 of SCO/DCO/RCO, 0..31; requires command Type IDs. */
  commandQualifiers?: number[];
  masters?: number[];
  outstations?: number[];
  groups?: number[];
  variations?: number[];
  instances?: number[];
  attributes?: number[];
  tags?: string[];
};

export type IEC104Class = "monitor" | "control" | "system" | "unknown";

/** Closed IEC 104 information object address range, 0..16777215. */
export type IOARange = {
  start: number;
  end: number;
};

/**
 * Enforcing terminals decide in list order: the first matching ALLOW, DENY
 * or RESET wins, otherwise the default action. RATE_LIMIT and TAG are effects.
 */
export type RuleAction = "ALLOW" | "DENY" | "RESET" | "RATE_LIMIT" | "TAG";

export type Position = "top" | "bottom" | { before: string } | { after: string };
export type FirewallRuleCreate = FirewallRule & { position?: Position };

type ForwardGrantWarning = {
  forwardId: string;
  ruleIds: string[];
  message: string;
  traffic: {
    sources: string[];
    ingressZone: string;
    backendZones: string;
    protocol: string;
    backend: string;
    listenAddress: string;
    listenPort: number;
  };
};

export type ForwardPlacement = {
  forwardId: string;
  overlap: string;
  ruleIds?: string[];
  index: number;
} & (
  | { reason: "generated"; rule: FirewallRule; warning?: never }
  | { reason: "inside"; rule?: never; warning?: never; ruleIds: string[] }
  | { reason: "partial"; rule?: never; warning: ForwardGrantWarning }
);

export type ForwardPublishResult = { forward: PortForward; placement?: ForwardPlacement };
export type ForwardDeleteResult = { deletedRuleIds: string[]; editedRuleIds: string[] };

/** Packet policer per directional 5-tuple; burst 0 means packetsPerSecond. */
export type RateLimit = {
  packetsPerSecond: number;
  burst?: number;
};

export type FirewallRule = {
  id: string;
  description?: string;
  sourceZones?: string[];
  destZones?: string[];
  sources?: string[];
  destinations?: string[];
  protocols?: Protocol[];
  ics?: ICSPredicate;
  identities?: string[];
  viaForwards?: string[];
  schedule?: RuleSchedule;
  action: RuleAction;
  /** Required for RATE_LIMIT, forbidden otherwise. */
  rateLimit?: RateLimit;
  /** Required for TAG, forbidden otherwise. */
  tag?: string;
  log?: boolean;
};

export type RuleSchedule = {
  daysOfWeek?: string[];
  startTime?: string;
  endTime?: string;
  timezone?: string;
};

/** Merge-PATCH selectors: null clears a restriction; omission retains it. */
export type ICSPredicatePatch = {
  [K in keyof ICSPredicate]?: ICSPredicate[K] | null;
};

/**
 * A firewall rule PATCH body. An omitted key keeps the stored value and
 * nested objects merge, so a cleared field is sent empty: `null` removes the
 * ICS predicate, rate limit or schedule.
 */
export type FirewallRulePatch = Partial<
  Omit<FirewallRule, "ics" | "rateLimit" | "schedule">
> & {
  ics?: ICSPredicatePatch | null;
  rateLimit?: RateLimit | null;
  schedule?: RuleSchedule | null;
};

/**
 * The part of a rule that makes it match nothing: identities no bound address
 * satisfies, zones none of which has an interface, or sources and
 * destinations that share no address family.
 */
export type RuleWarningPredicate = "identity" | "zone" | "addressFamily" | "forward";

/**
 * A firewall rule that does not act as written: it matches nothing because
 * of its `predicate`, or an earlier terminal covering all its traffic
 * shadows it (`shadowedBy`).
 */
export type RuleWarning = {
  ruleId: string;
  predicate?: RuleWarningPredicate;
  /** For predicate zone: the rule's zones without interfaces, sorted. */
  zones?: string[];
  shadowedBy?: string;
  action: RuleAction;
  message: string;
};

/** Rule impact preview: the rule matched in isolation against recent events. */
export type RulePreview = {
  /** Why historical counting is unavailable; counts and samples must not be shown. */
  unavailable?: string;
  match_count: number;
  /** The newest matching events, at most 50, in their original wire orientation. */
  sample_matches: TelemetryEvent[];
  /** Oldest and newest timestamps of the events searched; null when there were none. */
  time_range: { start: string; end: string } | null;
  total_events: number;
  warnings?: RuleWarning[];
  /** The candidate's ICS coverage under the running settings; absent without an ICS protocol. */
  icsCoverage?: ICSCoverageRule;
};

/**
 * Kernel accounting of one rule of the applied ruleset. A TAG rule counts
 * the connection openers it labels; excessDrops is RATE_LIMIT only.
 */
export type RuleCount = {
  ruleId: string;
  action: RuleAction;
  packets: number;
  bytes: number;
  excessDrops?: number;
};

/** Per-rule counters of the applied ruleset; every apply restarts them at `since`. */
export type RuleCounters = {
  snapshotVersion: string;
  since: string;
  rules: RuleCount[];
};

function counter(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

/** Null unless the body is a counters snapshot; a malformed entry is dropped. */
export function normalizeRuleCounters(value: unknown): RuleCounters | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const { snapshotVersion, since, rules } = value as Record<string, unknown>;
  if (typeof since !== "string" || since === "" || !Array.isArray(rules)) return null;
  return {
    snapshotVersion: typeof snapshotVersion === "string" ? snapshotVersion : "",
    since,
    rules: rules.flatMap((r) => {
      const rec = (r ?? {}) as Record<string, unknown>;
      const packets = counter(rec.packets);
      const bytes = counter(rec.bytes);
      if (typeof rec.ruleId !== "string" || packets === null || bytes === null) return [];
      const count: RuleCount = { ruleId: rec.ruleId, action: normalizeRuleAction(rec.action), packets, bytes };
      const excess = counter(rec.excessDrops);
      if (excess !== null) count.excessDrops = excess;
      return [count];
    }),
  };
}

/**
 * One firewall.identityBindings entry of the candidate: a unicast address
 * bound to 1-16 labels that rule identities match exactly.
 */
export type IdentityBinding = {
  ip: string;
  identities: string[];
};

function normalizeIdentityBindings(value: unknown): IdentityBinding[] {
  const mappings = (value as { mappings?: unknown } | null)?.mappings;
  if (!Array.isArray(mappings)) return [];
  return mappings.flatMap((m) => {
    const { ip, identities } = (m ?? {}) as Record<string, unknown>;
    if (typeof ip !== "string" || !Array.isArray(identities)) return [];
    return [{ ip, identities: identities.filter((id): id is string => typeof id === "string") }];
  });
}

export const firewallAPI = {
  listFirewallRules: async (signal?: AbortSignal) => {
    const rules = await getJSONList<unknown>("/api/v1/firewall/rules", signal);
    if (rules == null) return null;
    return normalizeFirewallRules(rules);
  },
  createFirewallRule: async (
    r: FirewallRuleCreate,
  ): Promise<ApiResult<FirewallRule & { index: number }>> => {
    const result = await postJSONResult<unknown>("/api/v1/firewall/rules", r);
    if (!result.ok) return result;
    return { ...result, data: { ...normalizeFirewallRule(result.data), index: (result.data as { index: number }).index } };
  },
  moveFirewallRule: async (id: string, position: Position): Promise<ApiResult<{ index: number; rules: FirewallRule[] }>> => {
    const result = await postJSONResult<{ index: number; rules: unknown[] }>(
      `/api/v1/firewall/rules/${encodeURIComponent(id)}/move`, { position },
    );
    return result.ok ? { ...result, data: { ...result.data, rules: normalizeFirewallRules(result.data.rules) } } : result;
  },
  publishPortForward: (forward: PortForward, allowRule = true) =>
    postJSONResult<ForwardPublishResult>("/api/v1/firewall/port-forwards", { forward, allowRule }),
  deletePortForward: (id: string) =>
    deleteJSONResult<ForwardDeleteResult>(`/api/v1/firewall/port-forwards/${encodeURIComponent(id)}`),
  updateFirewallRule: async (
    id: string,
    r: FirewallRulePatch,
  ): Promise<ApiResult<FirewallRule>> => {
    const result = await patchJSONResult<unknown>(
      `/api/v1/firewall/rules/${encodeURIComponent(id)}`,
      r,
    );
    if (!result.ok) return result;
    return { ...result, data: normalizeFirewallRule(result.data) };
  },
  // Matches the rule in isolation against recent events; stages nothing.
  previewFirewallRule: async (r: FirewallRule): Promise<ApiResult<RulePreview>> => {
    const res = await postJSONResult<RulePreview>("/api/v1/firewall/rules/preview", r);
    if (!res.ok) return res;
    const icsCoverage = normalizeICSCoverageRule(res.data?.icsCoverage) ?? undefined;
    return { ...res, data: { ...res.data, icsCoverage } };
  },
  deleteFirewallRule: (id: string) =>
    deleteJSONResult(`/api/v1/firewall/rules/${encodeURIComponent(id)}`),

  /** 502/503 when the engine has no readable applied ruleset; the error says why. */
  getRuleCounters: async (): Promise<ApiResult<RuleCounters>> => {
    const res = await getJSONResult<Record<string, unknown>>("/api/v1/firewall/counters");
    if (!res.ok) return res;
    const counters = normalizeRuleCounters(res.data);
    return counters ? { ok: true, data: counters } : { ok: false, error: "malformed counters response" };
  },

  listIdentityBindings: async (): Promise<ApiResult<IdentityBinding[]>> => {
    const res = await getJSONResult<Record<string, unknown>>("/api/v1/identities");
    return res.ok ? { ok: true, data: normalizeIdentityBindings(res.data) } : res;
  },
  /** Stages the binding, replacing any existing binding of its address. */
  setIdentityBinding: (b: IdentityBinding) =>
    postJSONResult<IdentityBinding>("/api/v1/identities", b),
  deleteIdentityBinding: (ip: string) =>
    deleteJSONResult(`/api/v1/identities/${encodeURIComponent(ip)}`),
};
