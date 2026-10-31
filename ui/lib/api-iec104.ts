import type {
  ICSDecisionAttributes,
  ICSEvidence,
  ICSSessionAttributes,
  ICSVerdictAttributes,
  TelemetryEvent,
} from "./api";

// Wire decoding of IEC 104 enforcement evidence events. Events
// come from the bounded event ring as untyped attribute maps; these readers
// return a typed view only when the required keys have the documented types.

const DECISIONS = new Set<ICSDecisionAttributes["decision"]>([
  "allow",
  "deny",
  "would_drop",
  "would_allow",
]);
const VERDICT_OUTCOMES = new Set<ICSVerdictAttributes["outcome"]>([
  "dropped",
  "drop_failed",
]);
const SESSION_OUTCOMES = new Set<ICSSessionAttributes["outcome"]>([
  "aborted",
  "reset_sent",
  "reset_failed",
  "reconnected",
  "enforce_unhealthy",
  "enforce_healthy",
]);

function str(a: Record<string, unknown>, k: string): string | undefined {
  const v = a[k];
  return typeof v === "string" ? v : undefined;
}

function uint(a: Record<string, unknown>, k: string): number | undefined {
  const v = a[k];
  return typeof v === "number" && Number.isInteger(v) && v >= 0 ? v : undefined;
}

function bool(a: Record<string, unknown>, k: string): boolean | undefined {
  const v = a[k];
  return typeof v === "boolean" ? v : undefined;
}

function oneOf<T extends string>(set: Set<T>, v: string | undefined): T | undefined {
  return v !== undefined && set.has(v as T) ? (v as T) : undefined;
}

function strings(a: Record<string, unknown>, k: string): string[] {
  const v = a[k];
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

/** Returns the session incarnation an IEC 104 event belongs to, if any. */
export function iec104SessionID(ev: TelemetryEvent): string | undefined {
  if (ev.proto !== "iec104" || !ev.attributes) return undefined;
  return str(ev.attributes, "session_id");
}

/** Decodes an `ics.decision`, `ics.verdict` or `ics.session` event. */
export function parseICSEvidence(ev: TelemetryEvent): ICSEvidence | null {
  if (!ev.attributes || (ev.proto !== "iec104" && ev.kind !== "ics.decision")) return null;
  const a = ev.attributes;
  // Session-scoped evidence carries session_id; an engine-wide health
  // change may have none, so a missing ID reads as "" rather than hiding it.
  const sessionID = str(a, "session_id") ?? "";

  if (ev.kind === "ics.decision") {
    const decision = oneOf(DECISIONS, str(a, "decision"));
    // The reason is free text from the engine: a reason this build does not
    // label is still evidence, so only a missing one hides the decision.
    const reason = str(a, "reason");
    if (!decision || !reason) return null;
    const direction = str(a, "direction");
    return {
      kind: "ics.decision",
      attrs: {
        session_id: sessionID,
        decision,
        reason,
        conformance: strings(a, "conformance"),
        ruleId: str(a, "ruleId") ?? "",
        action: str(a, "action"),
        mode: str(a, "mode"),
        scopeId: str(a, "scopeId"),
        findingCode: str(a, "findingCode"),
        apdu_id: str(a, "apdu_id"),
        type_id: uint(a, "type_id"),
        ca: uint(a, "ca"),
        ioa: uint(a, "ioa"),
        select: bool(a, "select"),
        direction:
          direction === "request" || direction === "response"
            ? direction
            : undefined,
      },
    };
  }

  if (ev.kind === "ics.verdict") {
    const outcome = oneOf(VERDICT_OUTCOMES, str(a, "outcome"));
    if (!outcome) return null;
    return {
      kind: "ics.verdict",
      attrs: {
        session_id: sessionID,
        outcome,
        apdu_ids: strings(a, "apdu_ids"),
        trigger_apdu_id: str(a, "trigger_apdu_id"),
        error: str(a, "error"),
      },
    };
  }

  if (ev.kind === "ics.session") {
    const outcome = oneOf(SESSION_OUTCOMES, str(a, "outcome"));
    if (!outcome) return null;
    const target = str(a, "target");
    return {
      kind: "ics.session",
      attrs: {
        session_id: sessionID,
        outcome,
        target: target === "client" || target === "server" ? target : undefined,
        error: str(a, "error"),
      },
    };
  }

  return null;
}
