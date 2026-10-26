import { parseICSEvidence, type TelemetryEvent } from "../../lib/api";
import { iec104TypeInfo } from "../ics/iec104";

// Presentation of IEC 104 enforcement evidence and APCI observations for
// Events, Alerts and Flows. Decoding and allow decisions do not prove delivery.

export type EvidenceSeverity = "critical" | "high" | "medium" | "low";
export type EvidenceVariant = "success" | "warning" | "error" | "info" | "neutral";
export type EvidenceRow = { label: string; value: string };

export type EvidenceView = {
  headline: string;
  badge: string;
  variant: EvidenceVariant;
  severity: EvidenceSeverity;
  message: string;
  rows: EvidenceRow[];
  sessionId: string;
  /** Allowed decisions are logged evidence, not alerts. */
  alert: boolean;
};

function typeLabel(typeId: number): string {
  const info = iec104TypeInfo(typeId);
  return `${typeId} ${info.name} (${info.cls})`;
}

function present(rows: Array<[string, string | number | boolean | undefined]>): EvidenceRow[] {
  return rows
    .filter(([, v]) => v !== undefined && v !== "")
    .map(([label, v]) => ({ label, value: String(v) }));
}

function objectText(a: { type_id?: number; ca?: number; ioa?: number }): string {
  return [
    a.type_id !== undefined ? `type ${a.type_id}` : "",
    a.ca !== undefined ? `CA ${a.ca}` : "",
    a.ioa !== undefined ? `IOA ${a.ioa}` : "",
  ]
    .filter(Boolean)
    .join(" ");
}

const DECISION_VIEW = {
  deny: { badge: "deny", variant: "error", severity: "high", headline: "IEC 104 APDU denied" },
  would_drop: { badge: "would drop", variant: "warning", severity: "medium", headline: "IEC 104 APDU would be dropped (learn)" },
  allow: { badge: "allow", variant: "success", severity: "low", headline: "IEC 104 APDU allowed by rule" },
} as const;

const REASON_TEXT: Record<string, string> = {
  rule: "matched rule",
  default: "no rule matched",
  broadcast: "broadcast CA",
  malformed: "malformed APDU",
  unsupported: "unsupported Type ID",
  role: "role violation",
};

const SESSION_VIEW = {
  aborted: { badge: "aborted", variant: "error", severity: "high", headline: "IEC 104 session aborted" },
  reset_sent: { badge: "reset sent", variant: "info", severity: "low", headline: "IEC 104 reset sent" },
  reset_failed: { badge: "reset failed", variant: "warning", severity: "critical", headline: "IEC 104 reset failed" },
  reconnected: { badge: "reconnected", variant: "success", severity: "low", headline: "IEC 104 session reconnected" },
  enforce_unhealthy: { badge: "unhealthy", variant: "warning", severity: "critical", headline: "IEC 104 enforcement unhealthy" },
  enforce_healthy: { badge: "healthy", variant: "success", severity: "low", headline: "IEC 104 enforcement healthy" },
} as const;

const APCI_ANOMALY_LABELS: Record<string, string> = {
  iec104_data_while_stopped: "IEC 104 data transfer not started",
  iec104_send_sequence: "IEC 104 send sequence anomaly",
  iec104_ack_sequence: "IEC 104 acknowledgement anomaly",
  iec104_test_timeout: "IEC 104 TESTFR confirmation timeout",
};

export function describeICSEvidence(ev: TelemetryEvent): EvidenceView | null {
  const attrs = ev.attributes ?? {};
  const anomalyType = String(attrs["anomaly_type"] ?? "");
  const anomalyLabel = Object.hasOwn(APCI_ANOMALY_LABELS, anomalyType)
    ? APCI_ANOMALY_LABELS[anomalyType]
    : undefined;
  if (ev.proto === "ids" && ev.kind === "anomaly" && anomalyLabel) {
    return {
      headline: anomalyLabel,
      badge: "observation",
      variant: "info",
      severity: "medium",
      message: String(attrs["message"] ?? anomalyLabel),
      sessionId: String(attrs["session_id"] ?? ""),
      alert: true,
      rows: [
        { label: "Anomaly", value: anomalyLabel },
        ...iec104AttributeRows(attrs),
      ],
    };
  }
  const evidence = parseICSEvidence(ev);
  if (!evidence) return null;

  if (evidence.kind === "ics.decision") {
    const a = evidence.attrs;
    const v = DECISION_VIEW[a.decision];
    const rule = a.ruleId || "envelope default";
    const what = objectText(a) || "APDU";
    return {
      ...v,
      message: `${v.badge}: ${what} (${REASON_TEXT[a.reason]}, ${rule})`,
      sessionId: a.session_id,
      alert: a.decision !== "allow",
      rows: present([
        ["Decision", a.decision],
        ["Reason", REASON_TEXT[a.reason]],
        ["Rule", rule],
        ["Rule action", a.action],
        ["Mode", a.mode],
        ["Type ID", a.type_id !== undefined ? typeLabel(a.type_id) : undefined],
        ["Common address", a.ca],
        ["IOA", a.ioa],
        ["Select", a.select],
        ["Direction", a.direction],
        ["APDU", a.apdu_id],
        ["Session", a.session_id],
      ]),
    };
  }

  if (evidence.kind === "ics.verdict") {
    const a = evidence.attrs;
    const dropped = a.outcome === "dropped";
    const count = `${a.apdu_ids.length} APDU${a.apdu_ids.length === 1 ? "" : "s"}`;
    return {
      headline: dropped ? "IEC 104 packets dropped" : "IEC 104 drop failed",
      badge: dropped ? "dropped" : "drop failed",
      variant: dropped ? "error" : "warning",
      severity: dropped ? "high" : "critical",
      message: dropped
        ? `Dropped ${count} of an aborted session`
        : `Drop failed: ${a.error ?? "no error reported"}`,
      sessionId: a.session_id,
      alert: true,
      rows: present([
        ["Outcome", a.outcome],
        ["Dropped APDUs", a.apdu_ids.length > 0 ? a.apdu_ids.join(", ") : "none identified"],
        ["Trigger APDU", a.trigger_apdu_id ?? "none (timeout, queue or transport abort)"],
        ["Error", a.error],
        ["Session", a.session_id],
      ]),
    };
  }

  const a = evidence.attrs;
  const v = SESSION_VIEW[a.outcome];
  const target = a.target ? ` to ${a.target}` : "";
  return {
    ...v,
    message: `${v.headline}${target}${a.error ? `: ${a.error}` : ""}`,
    sessionId: a.session_id,
    alert: true,
    rows: present([
      ["Outcome", a.outcome],
      ["Target", a.target],
      ["Error", a.error],
      ["Session", a.session_id],
    ]),
  };
}

/** Readable rows for a decoded IEC 104 event, e.g. in an alert. */
export function iec104AttributeRows(attrs: Record<string, unknown>): EvidenceRow[] {
  const typeId = attrs["type_id"];
  const scalar = (k: string) => {
    const v = attrs[k];
    return typeof v === "string" || typeof v === "number" || typeof v === "boolean"
      ? v
      : undefined;
  };
  return present([
    ["APCI", scalar("apci_type")],
    ["U function", scalar("u_function")],
    ["N(S)", scalar("send_sequence")],
    ["Expected N(S)", scalar("expected_send_sequence")],
    ["N(R)", scalar("receive_sequence")],
    ["Last acknowledged", scalar("last_acked")],
    ["Next unsent", scalar("next_unsent")],
    ["t1 (seconds)", scalar("t1_seconds")],
    ["Type ID", typeof typeId === "number" ? typeLabel(typeId) : undefined],
    ["Class", scalar("class")],
    ["Direction", scalar("direction")],
    ["Cause", scalar("cause")],
    ["Negative", scalar("cot_negative")],
    ["Test", scalar("cot_test")],
    ["Common address", scalar("ca")],
    ["IOA", scalar("ioa")],
    ["Select", scalar("select")],
    ["Value", scalar("value")],
    ["Qualifier", scalar("qualifier")],
    ["Quality", scalar("quality")],
    ["Source time", scalar("source_time")],
    ["Mutating request", scalar("is_write")],
    ["Error", scalar("error")],
    ["APDU", scalar("apdu_id")],
    ["Session", scalar("session_id")],
  ]);
}
