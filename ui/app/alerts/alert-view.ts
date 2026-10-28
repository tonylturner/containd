import type { TelemetryEvent } from "../../lib/api";
import { describeICSEvidence, type EvidenceSeverity, type EvidenceView } from "../events/iec104-evidence";

export type AlertView = {
  severity: EvidenceSeverity;
  message: string;
  protocol: string;
  section: string;
  identifier?: { label: string; value: string };
  description: string;
  triggeredBy: string;
  evidence?: EvidenceView;
};

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function severity(value: unknown): EvidenceSeverity {
  const normalized = text(value).toLowerCase();
  switch (normalized) {
    case "critical":
    case "high":
    case "medium":
      return normalized;
    default:
      return "low";
  }
}

/** Present producer fields without treating every derived event as a rule match. */
export function alertView(event: TelemetryEvent): AlertView | null {
  const attrs = event.attributes ?? {};
  const base = {
    severity: severity(attrs["severity"]),
    description: text(attrs["description"]),
    triggeredBy: "",
  };

  // Keep IEC 104's observational labels and non-allow enforcement evidence.
  const evidence = describeICSEvidence(event);
  if (evidence) {
    return evidence.alert ? {
      ...base, evidence, severity: evidence.severity, message: evidence.message,
      protocol: "iec104", section: "IEC 104 Evidence",
    } : null;
  }
  if (event.proto !== "ids") return null;

  switch (event.kind) {
    case "alert": {
      const id = text(attrs["rule_id"]);
      const eventProto = text(attrs["event_proto"]);
      return {
        ...base, section: "Rule", protocol: eventProto || text(attrs["protocol"]),
        message: text(attrs["message"]) || id || "IDS alert",
        identifier: id ? { label: "Rule ID", value: id } : undefined,
        triggeredBy: [eventProto, text(attrs["event_kind"])].filter(Boolean).join(" / "),
      };
    }
    case "anomaly": {
      const type = text(attrs["anomaly_type"]);
      return {
        ...base, section: "Anomaly", protocol: text(attrs["protocol"]),
        message: text(attrs["message"]) || type || "Protocol anomaly",
        identifier: type ? { label: "Anomaly type", value: type } : undefined,
      };
    }
    case "signature_match": {
      const id = text(attrs["signature_id"]);
      return {
        ...base, section: "Signature", protocol: "",
        message: text(attrs["name"]) || id || "Signature match",
        identifier: id ? { label: "Signature ID", value: id } : undefined,
      };
    }
    default:
      return null;
  }
}
