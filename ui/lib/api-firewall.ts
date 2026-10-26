import {
  deleteJSONResult,
  getJSON,
  patchJSONResult,
  postJSONResult,
} from "./api-request";
import { normalizeFirewallRule, normalizeFirewallRules } from "./api-normalize";
import { normalizeICSCoverageRule, type ICSCoverageRule } from "./api-ics-coverage";

import type { ApiResult } from "./api";

export type Protocol = {
  name: string;
  port?: string;
};

export type ICSPredicate = {
  protocol?: string;
  functionCode?: number[];
  unitId?: number;
  addresses?: string[];
  objectClasses?: number[];
  readOnly?: boolean;
  writeOnly?: boolean;
  direction?: "request" | "response";
  mode?: "enforce" | "learn";
  // IEC 60870-5-104 fields (protocol "iec104"). A missing field is a
  // wildcard; an empty list is a validation error, so never send [].
  typeIds?: number[];
  classes?: IEC104Class[];
  ca?: number[];
  ioa?: IOARange[];
};

export type IEC104Class = "monitor" | "control" | "system" | "unknown";

/** Closed IEC 104 information object address range, 0..16777215. */
export type IOARange = {
  start: number;
  end: number;
};

/**
 * ALLOW, DENY and RESET decide: any matching ALLOW admits the packet,
 * otherwise the first matching DENY or RESET by rule ID decides, otherwise
 * the default action. RATE_LIMIT and TAG are effects that never admit.
 */
export type RuleAction = "ALLOW" | "DENY" | "RESET" | "RATE_LIMIT" | "TAG";

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

/** An ICS predicate patch; `mode: ""` clears a stored mode so it inherits. */
export type ICSPredicatePatch = Omit<ICSPredicate, "mode"> & {
  mode?: ICSPredicate["mode"] | "";
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
 * A firewall rule that does not act as written: its identities match no
 * bound address (`predicate: "identity"`), so it matches nothing, or it is a
 * DENY or RESET rule that an ALLOW matching all of its traffic shadows
 * (`shadowedBy`).
 */
export type RuleWarning = {
  ruleId: string;
  predicate?: "identity";
  shadowedBy?: string;
  action: RuleAction;
  message: string;
};

/** Rule impact preview: the rule matched in isolation against recent events. */
export type RulePreview = {
  match_count: number;
  sample_matches: unknown[];
  time_range: { start: string; end: string } | null;
  total_events: number;
  warnings?: RuleWarning[];
  /** The candidate's ICS coverage under the running settings; absent without an ICS protocol. */
  icsCoverage?: ICSCoverageRule;
};

export const firewallAPI = {
  listFirewallRules: async (signal?: AbortSignal) => {
    const rules = await getJSON<unknown>("/api/v1/firewall/rules", signal);
    if (rules == null) return null;
    return normalizeFirewallRules(rules);
  },
  createFirewallRule: async (
    r: FirewallRule,
  ): Promise<ApiResult<FirewallRule>> => {
    const result = await postJSONResult<unknown>("/api/v1/firewall/rules", r);
    if (!result.ok) return result;
    return { ...result, data: normalizeFirewallRule(result.data) };
  },
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
};
