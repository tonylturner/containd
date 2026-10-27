import type {
  FirewallRule,
  RateLimit,
  RuleAction,
  RuleSchedule,
} from "../../lib/api";
import { parseIdentityLabels } from "../../lib/validate";

// The action and conditions of a firewall rule form: what the rule does
// (action, rate limit, tag) and when it applies (identities, schedule).

export type ActionInfo = {
  value: RuleAction;
  /** ALLOW, DENY and RESET decide; RATE_LIMIT and TAG are effects. */
  decides: boolean;
  help: string;
};

export const RULE_ACTIONS: ActionInfo[] = [
  { value: "ALLOW", decides: true, help: "Accepts the packet. Any matching ALLOW wins over every DENY and RESET." },
  { value: "DENY", decides: true, help: "Drops the packet when no ALLOW matches." },
  { value: "RESET", decides: true, help: "Rejects back to the sender when no ALLOW matches: a TCP reset for TCP, ICMP administratively prohibited otherwise." },
  { value: "RATE_LIMIT", decides: false, help: "Effect: drops the packets over the limit for each directional 5-tuple. Packets under the limit continue to the ALLOW/DENY decision." },
  { value: "TAG", decides: false, help: "Effect: labels matching connections and their events. It never admits or drops traffic." },
];

export function actionInfo(action: RuleAction): ActionInfo {
  return RULE_ACTIONS.find((a) => a.value === action) ?? RULE_ACTIONS[1];
}

/** Only ALLOW and DENY rules take an ICS protocol. */
export function actionTakesICS(action: RuleAction): boolean {
  return action === "ALLOW" || action === "DENY";
}

export function actionVariant(action: RuleAction): "success" | "error" | "warning" | "info" {
  switch (action) {
    case "ALLOW":
      return "success";
    case "RATE_LIMIT":
      return "warning";
    case "TAG":
      return "info";
    default:
      return "error";
  }
}

export const WEEKDAYS = [
  "Sunday",
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
] as const;

export const MAX_RATE_PPS = 1_000_000;
export const MAX_RATE_BURST = 1_000_000;
export const MAX_TAG_LABELS = 32;
const TAG_RE = /^[a-z0-9][a-z0-9_.-]{0,31}$/;
const TIME_RE = /^([01][0-9]|2[0-3]):[0-5][0-9]$/;

/** The form state of a rule's action and conditions. */
export type PolicyDraft = {
  action: RuleAction;
  pps: string;
  burst: string;
  tag: string;
  identities: string;
  scheduled: boolean;
  days: string[];
  start: string;
  end: string;
  timezone: string;
};

export function policyDraftFrom(rule?: FirewallRule): PolicyDraft {
  const s = rule?.schedule;
  return {
    action: rule?.action ?? "ALLOW",
    pps: rule?.rateLimit ? String(rule.rateLimit.packetsPerSecond) : "",
    burst: rule?.rateLimit?.burst ? String(rule.rateLimit.burst) : "",
    tag: rule?.tag ?? "",
    identities: (rule?.identities ?? []).join(", "),
    scheduled: !!s,
    days: WEEKDAYS.filter((d) => s?.daysOfWeek?.includes(d)),
    start: s?.startTime ?? "",
    end: s?.endTime ?? "",
    timezone: s?.timezone ?? "",
  };
}

/** What a valid draft stages; absent fields are not set on the rule. */
export type PolicyFields = {
  action: RuleAction;
  rateLimit?: RateLimit;
  tag?: string;
  identities: string[];
  schedule?: RuleSchedule;
};

type Built<T> = { ok: true; value: T } | { ok: false; error: string };

/**
 * Validates a draft against the server's bounds. `tagsInUse` are the
 * distinct TAG labels of the other rules, for the per-config label limit.
 */
export function buildPolicy(draft: PolicyDraft, tagsInUse: string[]): Built<PolicyFields> {
  const identities = parseIdentityLabels(draft.identities);
  if (!identities.ok) return { ok: false, error: `Identities: ${identities.error}` };
  const fields: PolicyFields = { action: draft.action, identities: identities.labels };

  if (draft.action === "RATE_LIMIT") {
    const rateLimit = buildRateLimit(draft.pps, draft.burst);
    if (!rateLimit.ok) return rateLimit;
    fields.rateLimit = rateLimit.value;
  }
  if (draft.action === "TAG") {
    const tag = draft.tag.trim();
    if (!TAG_RE.test(tag)) {
      return { ok: false, error: "Tag: use 1-32 characters a-z, 0-9, '_', '.' and '-', starting with a letter or digit." };
    }
    if (!tagsInUse.includes(tag) && new Set(tagsInUse).size >= MAX_TAG_LABELS) {
      return { ok: false, error: `Tag: a configuration uses at most ${MAX_TAG_LABELS} distinct tag labels.` };
    }
    if (draft.scheduled) {
      return { ok: false, error: "Schedule: a TAG rule takes no schedule; its label is fixed when the connection opens." };
    }
    fields.tag = tag;
  }
  if (draft.scheduled) {
    const schedule = buildSchedule(draft);
    if (!schedule.ok) return schedule;
    fields.schedule = schedule.value;
  }
  return { ok: true, value: fields };
}

function parseBound(raw: string, min: number, max: number): number | null {
  const s = raw.trim();
  if (!/^\d+$/.test(s)) return null;
  const n = Number(s);
  return n >= min && n <= max ? n : null;
}

function buildRateLimit(pps: string, burst: string): Built<RateLimit> {
  const packetsPerSecond = parseBound(pps, 1, MAX_RATE_PPS);
  if (packetsPerSecond === null) {
    return { ok: false, error: `Rate limit: packets per second must be a whole number from 1 to ${MAX_RATE_PPS}.` };
  }
  const b = burst.trim() === "" ? 0 : parseBound(burst, 0, MAX_RATE_BURST);
  if (b === null) {
    return { ok: false, error: `Rate limit: burst must be a whole number from 0 to ${MAX_RATE_BURST} (0 means packets per second).` };
  }
  return { ok: true, value: b > 0 ? { packetsPerSecond, burst: b } : { packetsPerSecond } };
}

function validTimezone(tz: string): boolean {
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

function buildSchedule(draft: PolicyDraft): Built<RuleSchedule> {
  const start = draft.start.trim();
  const end = draft.end.trim();
  const timezone = draft.timezone.trim();
  for (const [label, value] of [["start", start], ["end", end]] as const) {
    if (value !== "" && !TIME_RE.test(value)) {
      return { ok: false, error: `Schedule: ${label} time must be 24-hour HH:MM.` };
    }
  }
  // A blank start is 00:00, so a blank start and an end of 00:00 are equal.
  if (end !== "" && (start || "00:00") === end) {
    return { ok: false, error: "Schedule: start and end times must differ." };
  }
  if (draft.days.length === 0 && start === "" && end === "") {
    return { ok: false, error: "Schedule: choose days or a time window, or turn the schedule off." };
  }
  if (timezone !== "" && !validTimezone(timezone)) {
    return { ok: false, error: `Schedule: "${timezone}" is not an IANA timezone.` };
  }
  const schedule: RuleSchedule = {};
  if (draft.days.length > 0) schedule.daysOfWeek = WEEKDAYS.filter((d) => draft.days.includes(d));
  if (start) schedule.startTime = start;
  if (end) schedule.endTime = end;
  if (timezone) schedule.timezone = timezone;
  return { ok: true, value: schedule };
}

/** Distinct TAG labels of the rules other than `exceptId`. */
export function tagsInUse(rules: FirewallRule[], exceptId?: string): string[] {
  return [...new Set(rules.filter((r) => r.id !== exceptId && r.tag).map((r) => r.tag as string))];
}

export function formatRateLimit(rl: RateLimit): string {
  return `${rl.packetsPerSecond} pps, burst ${rl.burst || rl.packetsPerSecond}`;
}

/** "Mon,Tue 02:00-06:00 America/New_York"; blank times read as the day's bounds. */
export function formatSchedule(s: RuleSchedule): string {
  const days = s.daysOfWeek?.length ? s.daysOfWeek.map((d) => d.slice(0, 3)).join(",") : "daily";
  const window = s.startTime || s.endTime ? ` ${s.startTime || "00:00"}-${s.endTime || "24:00"}` : "";
  return `${days}${window} ${s.timezone || "UTC"}`;
}
