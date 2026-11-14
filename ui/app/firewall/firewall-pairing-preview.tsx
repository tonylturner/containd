import type { PairingPreview } from "../../lib/api";

const outcomes = ["paired", "unpaired", "expired", "ambiguous", "unsupported", "unknown"] as const;
const reasons: Record<string, string> = {
  paired: "Compatible request or explicit class rule observed",
  unpaired: "No compatible allowed request",
  pairing_expired: "Request expired, was evicted or lost authorization",
  pairing_ambiguous: "More than one request could match",
  pairing_unsupported: "Procedure is unsupported for pairing",
  pairing_unknown: "Pairing authority is missing or historical evidence is unstamped",
  pairing_mismatch: "Reply fields or stage do not match the request",
  autonomous_rule_required: "Autonomous data needs an explicit autonomous rule",
  session_rule_required: "Session controls need an explicit session rule",
  message_timeout: "A complete unit did not arrive within the hold deadline",
  state_limit: "Inspection state capacity was exhausted",
};

/** Separate observed pairing facts from candidate predicate match counts. */
export function PairingPreviewSummary({ pairing }: { pairing?: PairingPreview }) {
  if (!pairing) return null;
  return (
    <section aria-label="Retained pairing outcomes" className="mt-3 space-y-2 rounded-xs border bg-(--surface) p-3 text-xs text-(--text)">
      <h3 className="font-semibold">Retained pairing outcomes</h3>
      <p className="text-(--text-muted)">Runtime stamps on selected events, not candidate admission or delivery. Unstamped historical evidence is unknown.</p>
      <dl className="flex flex-wrap gap-x-5 gap-y-2">
        {outcomes.map(outcome => <div key={outcome}><dt className="capitalize">{outcome}</dt><dd className="font-mono">{pairing[outcome]}</dd></div>)}
      </dl>
      {pairing.reasons.length > 0 && <ul aria-label="Pairing reasons" className="space-y-1">
        {pairing.reasons.map(reason => <li key={reason}>{reasons[reason] ?? "Runtime pairing reason"} <code className="break-all">({reason})</code></li>)}
      </ul>}
      <p className="text-(--text-muted)">In enforce mode, unpaired, late, ambiguous, mismatched or unsupported replies reset the session. Reconnect after a reset. Reply deadlines: Modbus/DNP3 30 s; IEC 15 s, or 30 s for interrogations. All bytes of an IEC unit must arrive within the separate 1 s hold; slow devices and gateways can exceed these bounds.</p>
    </section>
  );
}
