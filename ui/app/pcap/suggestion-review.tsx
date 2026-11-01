"use client";

import { useState } from "react";
import { api, type FirewallRule, type RulePreview } from "../../lib/api";
import { type LearnSuggestion, selectable } from "../../lib/api-learn";
import { summarizeGenericICS } from "../ics/ics-shared";
import { summarizeIEC104 } from "../ics/iec104";
import { RuleImpactSummary } from "../firewall/firewall-rule-warnings";

export const secondaryButton =
  "rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui disabled:opacity-30 disabled:cursor-not-allowed";
export const primaryButton =
  "rounded-xs bg-(--amber) px-3 py-1.5 text-sm font-medium text-black transition-ui hover:brightness-110 disabled:opacity-40";

function RuleScope({
  rule,
  canEdit,
}: {
  rule: FirewallRule;
  canEdit: boolean;
}) {
  const [preview, setPreview] = useState<RulePreview | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const ics = rule.ics;
  const iec = ics && summarizeIEC104(ics);
  return (
    <li className="space-y-2 border-t py-3 first:border-t-0">
      <p className="break-all font-mono text-xs">
        {rule.description || rule.id}
      </p>
      <p className="break-words text-sm">
        {(rule.sources ?? []).join(", ") || "any"} →{" "}
        {(rule.destinations ?? []).join(", ") || "any"}
      </p>
      <p className="text-xs">
        Service:{" "}
        {(rule.protocols ?? [])
          .map((p) => `${p.name}/${p.port || "any"}`)
          .join(", ") || "any"}{" "}
        · {rule.action} · {ics?.mode}
      </p>
      {ics && (
        <p className="text-xs">
          {ics.protocol} ·{" "}
          {ics.protocol === "iec104"
            ? `${iec?.types} ${iec?.addresses}`
            : summarizeGenericICS(ics)}
        </p>
      )}
      {canEdit && (
        <button
          className={secondaryButton}
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            setError("");
            const res = await api.previewFirewallRule(rule);
            setBusy(false);
            if (res.ok) setPreview(res.data);
            else {
              setError(res.error);
              setPreview(null);
            }
          }}
        >
          {busy ? "Previewing…" : "Preview live recent evidence"}
        </button>
      )}
      {error && (
        <p role="alert" className="text-sm text-(--red)">
          {error}
        </p>
      )}
      {preview && (
        <div>
          <h4 className="text-sm font-semibold">Live recent evidence</h4>
          <p className="text-xs text-(--text-muted)">
            Isolated rule impact, not frozen certification or a whole-policy
            simulation.
          </p>
          <RuleImpactSummary preview={preview} />
        </div>
      )}
    </li>
  );
}

export function SuggestionReview({
  suggestion: s,
  now,
  checked,
  changedSinceSelected,
  canEdit,
  busy,
  onToggle,
  onReview,
}: {
  suggestion: LearnSuggestion;
  now: number;
  checked: boolean;
  changedSinceSelected?: boolean;
  canEdit: boolean;
  busy: boolean;
  onToggle: () => void;
  onReview: (approve: boolean, coordinates: boolean) => void;
}) {
  const [coordinates, setCoordinates] = useState(false);
  const iec = s.content.rules.some((r) => r.ics?.protocol === "iec104");
  const expired = Date.parse(s.expiresAt) <= now;
  const reviewable =
    !expired && !!s.proof && ["certified", "reviewed"].includes(s.status);
  const failures = s.proof
    ? s.proof.positive.failed + s.proof.negative.failed
    : 0;
  const counterexamples = s.proof?.counterexamples?.length ?? 0;
  const limitations = s.content.limits?.length
    ? s.content.limits
    : [
        "Exact within supported selector relations, not byte-for-byte transaction equality. Finite replay is not universal protocol correctness.",
      ];
  const warnings = [
    ...new Set([
      ...(!s.proof ? ["No certification; cannot stage."] : []),
      ...(failures ? [`${failures} replay failure(s).`] : []),
      ...(counterexamples ? [`${counterexamples} counterexample(s).`] : []),
      ...(expired ? ["Evidence expired."] : []),
      ...limitations,
      ...(s.content.withheld ?? []),
    ]),
  ];
  return (
    <article
      aria-label={`Suggestion ${s.id}`}
      className="min-w-0 space-y-3 border-t py-4"
    >
      {changedSinceSelected && <p role="status" className="mb-2 text-sm text-(--amber)">Changed since selected — review this revision and select it again.</p>}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <h3 className="break-all font-mono text-sm">{s.id}</h3>
          <p className="text-xs text-(--text-muted)">
            Revision {s.revision} · {expired ? "expired" : s.status} ·{" "}
            {s.status === "staged"
              ? "Staged receipt — not proof of activation"
              : "Not staged"}
          </p>
          <p className="text-xs text-(--text-muted)">
            Expires {new Date(s.expiresAt).toLocaleString()}
          </p>
        </div>
        {canEdit && (
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              aria-label={`Select ${s.id}`}
              checked={checked}
              disabled={busy || !selectable(s, now)}
              onChange={onToggle}
            />
            Select
          </label>
        )}
      </div>
      <p className="text-sm">
        Authority:{" "}
        {s.content.requiresCoordinateReview
          ? "wire coordinates; verify pre-NAT capture scope against deployment"
          : "logical policy coordinates"}
        .
      </p>
      {iec && (
        <p className="text-sm text-(--amber)">
          IEC 104 requires explicit admin Review before selection. Staged IEC
          rules arrive as monitor, never enforce.
        </p>
      )}
      <ul aria-label="Proposed rules">
        {s.content.rules.map((r) => (
          <RuleScope key={r.id} rule={r} canEdit={canEdit} />
        ))}
      </ul>
      <details
        aria-label="Frozen certification"
        className="rounded-xs border bg-(--surface) p-3"
      >
        <summary className="cursor-pointer text-sm font-semibold">
          Certified evidence (frozen)
          {s.proof && (
            <>
              {" · replay "}
              {s.proof.positive.passed}/{s.proof.positive.total}
              {" · boundaries "}
              {s.proof.negative.passed}/{s.proof.negative.total}
            </>
          )}
          {" · "}
          <span
            aria-label="Certification warnings"
            className="font-normal text-(--amber)"
          >
            {warnings.join(" ")}
          </span>
        </summary>
        {s.proof ? (
          <div className="mt-2 space-y-1 break-words text-xs">
            <p>
              Positive replay: {s.proof.positive.passed}/
              {s.proof.positive.total} passed, {s.proof.positive.failed} failed.
            </p>
            <p>
              Negative boundaries: {s.proof.negative.passed}/
              {s.proof.negative.total} passed, {s.proof.negative.failed} failed.
            </p>
            <p>
              {s.proof.parentRefs?.length ?? 0} parent references · certified{" "}
              {new Date(s.proof.certifiedAt).toLocaleString()}
            </p>
            <p className="break-all">
              Evidence digest: {s.proof.evidenceDigest}
            </p>
            <p className="break-all">Content: {s.proof.contentId}</p>
            <p className="break-all">
              Versions:{" "}
              {Object.entries(s.proof.versions)
                .map(([k, v]) => `${k}=${v}`)
                .join(" · ")}
            </p>
            {(s.proof.counterexamples ?? []).map((c, i) => (
              <p key={i}>
                {c.mutation}: expected {c.expected}, got {c.actual}
              </p>
            ))}
          </div>
        ) : (
          <p className="mt-2 text-sm">
            No certification available. Cannot stage.
          </p>
        )}
      </details>
      {(s.legacyOverlaps ?? []).map((o) => (
        <p key={o.ruleId} className="break-words text-xs text-(--amber)">
          Legacy overlap {o.ruleId}: {o.reason}. Warning only; no existing rule
          is removed.
        </p>
      ))}
      {s.review && (
        <p className="text-xs">
          Reviewed by {s.review.actor} at{" "}
          {new Date(s.review.at).toLocaleString()}; coordinates{" "}
          {s.review.coordinateApproved ? "approved" : "not approved"}.
        </p>
      )}
      {canEdit && reviewable && (
        <div className="space-y-2">
          {s.content.requiresCoordinateReview && (
            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-1"
                checked={coordinates}
                disabled={busy}
                onChange={(e) => setCoordinates(e.target.checked)}
              />
              I verified the wire addresses and service against policy/NAT
              coordinates.
            </label>
          )}
          <div className="flex flex-wrap gap-2">
            <button
              className={secondaryButton}
              disabled={
                busy || (s.content.requiresCoordinateReview && !coordinates)
              }
              onClick={() => onReview(true, coordinates)}
            >
              Review and approve
            </button>
            <button
              className={secondaryButton}
              disabled={busy}
              onClick={() => onReview(false, false)}
            >
              Reject
            </button>
          </div>
          <p className="text-xs text-(--text-muted)">
            Review records approval of this revision. It does not select, stage
            or activate rules.
          </p>
        </div>
      )}
    </article>
  );
}
