"use client";

import { revisionError } from "../../lib/config-revision";

import { useCallback, useState } from "react";
import { useAsyncRefresh } from "../../hooks/useAsyncRefresh";
import { Card } from "../../components/Card";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import { api, type ApiResult } from "../../lib/api";
import { ConfigDiffBlocks } from "../config/config-diff-blocks";
import { buildDiffBlocks } from "../config/config-utils";
import type { ConfigDiff } from "../../lib/api-config";
import { useConfigView } from "../../lib/use-config-revision";
import {
  learner,
  selectable,
  stageSuggestions,
  type LearnApplyRequest,
  type LearnDataset,
  type LearnObservation,
  type LearnPage,
  type LearnSuggestion,
} from "../../lib/api-learn";
import { useConfigRefresh } from "../../lib/use-config-refresh";
import {
  SuggestionReview,
  primaryButton,
  secondaryButton,
} from "./suggestion-review";

export function dataOf<T>(res: ApiResult<T>): T {
  if (!res.ok) throw new Error(res.error);
  return res.data;
}
export function ReasonCounts({
  counts,
}: {
  counts: Record<string, number> | null;
}) {
  const labels: Record<string, string> = {
    iec104_value: "IEC command withheld: value not expressible",
    iec104_qualifier: "IEC command withheld: qualifier not expressible",
    iec104_sbo_sequence: "IEC command withheld: select-before-operate sequence",
    cip_observation_only: "CIP observations only; no actionable rules",
    nonstandard_port: "Nonstandard service: observation only",
    replay_failed: "Recorded-traffic check failed",
    collection_loss: "Connection excluded: collection loss may hide observations",
  };
  return (
    <ul className="mt-2 space-y-1 break-words text-xs">
      {Object.entries(counts ?? {}).map(([reason, count]) => (
        <li key={reason}>
          <span>{labels[reason] || "Unrecognized reason"}: {count}</span>
          <details className="mt-1">
            <summary className="cursor-pointer">Technical details</summary>
            <code>{reason}</code>
          </details>
        </li>
      ))}
    </ul>
  );
}

export function DatasetReview({
  dataset,
  now,
  canEdit,
  onChanged,
}: {
  dataset: LearnDataset;
  now: number;
  canEdit: boolean;
  onChanged: () => Promise<void>;
}) {
  const [loadedSuggestions, setSuggestions] =
    useState<LearnPage<LearnSuggestion> | null>(null);
  const [observations, setObservations] =
    useState<LearnPage<LearnObservation> | null>(null);
  const [selected, setSelected] = useState<Map<string, number>>(new Map());
  const [withheld, setWithheld] = useState<Record<string, number> | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [receipt, setReceipt] = useState<LearnApplyRequest | null>(null);
  const revision = useConfigView<ConfigDiff | null>(null);
  const destination = revision.available ? revision.data : null;
  const { readConfig, requireReview } = revision;
  const baseRevision = revision.state.baseRevision;
  const [uncertain, setUncertain] = useState(false);
  const needsReview = !!revision.state.conflictRevision || !!revision.state.revisionRequired;
  const confirm = useConfirm();

  const { loading, refresh } = useAsyncRefresh(useCallback(async ({ discard = false }: { discard?: boolean } = {}) => {
    try {
      setSuggestions(dataOf(await learner.suggestions(dataset.id)));
    } catch (e) {
      setSuggestions(null);
      setError(String(e));
    }
    // Destination refresh is comparison context, not permission to rebase a receipt.
    const snapshot = await api.diffConfig();
    readConfig(snapshot, !discard, true);
    if (snapshot && discard) { setReceipt(null); setSelected(new Map()); setUncertain(false); }
  }, [dataset.id, readConfig]));
  const suggestions = loading ? null : loadedSuggestions;
  useConfigRefresh(refresh);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await action();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  async function stage(payload: LearnApplyRequest) {
    if (!baseRevision || needsReview || !destination || !revision.writable) return;
    setReceipt(payload);
    const res = await revision.writeRefresh(base => stageSuggestions(payload, base), api.diffConfig);
    if (res.ok) {
      setReceipt(null);
      if (res.adopted) setSelected(new Map());
      setUncertain(false);
      setNotice(
        `${payload.selections.length} suggestion(s) staged — not active. Review the candidate diff and commit to apply monitor rules.`,
      );
    } else {
      // Network/5xx can follow durable candidate persistence. Never invent a new receipt.
      const uncertain = !res.status || res.status >= 500;
      setReceipt(res.status === 412 || uncertain ? payload : null);
      setUncertain(uncertain);
      if (uncertain) requireReview();
      setError(revisionError(res) ?? "");
    }
    await refresh();
    await onChanged();
  }
  const eligible = (suggestions?.items ?? []).filter(
    (s) => selected.get(s.id) === s.revision && selectable(s, now),
  );
  const ruleCount = eligible.reduce((n, s) => n + s.content.rules.length, 0);
  return (
    <Card title="Dataset review" className="mt-6 min-w-0">
      <ConfirmDialog {...confirm.props} />
      <div className="flex flex-wrap justify-between gap-3">
        <h2 className="break-all font-mono text-sm">{dataset.id}</h2>
        <button
          className={secondaryButton}
          disabled={busy}
          onClick={() => void run(() => refresh())}
        >
          Refresh suggestions
        </button>
      </div>
      <p className="mt-2 text-sm">
        {dataset.source} · {dataset.state} · {dataset.records} records ·{" "}
        {dataset.bytes.toLocaleString()} bytes
      </p>
      <p className="text-xs text-(--text-muted)">
        Created {new Date(dataset.createdAt).toLocaleString()} · expires{" "}
        {new Date(dataset.expiresAt).toLocaleString()}
      </p>
      <details className="mt-3 text-xs">
        <summary className="cursor-pointer">
          Collection details
        </summary>
        <dl className="mt-2 space-y-1 break-all">
          {Object.entries({
            "File checksum (SHA-256)": dataset.captureSha256 || "Live source",
            "Evidence checksum": dataset.evidenceDigest,
            "Protocol reader version": dataset.decoderVersion,
            "Inspection profile ID": dataset.profileFingerprint,
            "Configuration ID": dataset.snapshotFingerprint,
          }).map(([k, v]) => (
            <div key={k}>
              <dt className="inline font-semibold">{k}: </dt>
              <dd className="inline">{v}</dd>
            </div>
          ))}
        </dl>
      </details>
      {!!dataset.gaps?.length && (
        <div role="status" className="mt-3 break-words text-sm text-(--amber)">
          Collection limitations reported. Localized loss excludes
          only connections it could have touched. Timestamp-only loss, missing
          scope, restart and policy-change loss exclude the entire dataset.
          <details>
            <summary className="cursor-pointer">Collection limitation details</summary>
            <code>{dataset.gaps.join(", ")}</code>
          </details>
        </div>
      )}
      <p className="mt-3 text-xs text-(--text-muted)">
        Import and collection never generate or stage policy. Generate
        explicitly after collection finishes. Selection is not approval; every generated
        rule is saved in monitor mode, not blocking mode.
      </p>
      {error && (
        <div role="alert" className="mt-3 break-words text-sm text-(--red)">
          Could not complete this collection action.
          <p>{error}</p>
        </div>
      )}
      {notice && (
        <p role="status" className="mt-3 text-sm text-(--green)">
          {notice}
        </p>
      )}
      {receipt && (
        <div className="mt-3 space-y-2 text-sm">
          <p>
            {uncertain ? "Staging completion is uncertain; the candidate may already contain this batch. Review the destination before retrying the same receipt." : "Staging did not complete. Your selections and the original receipt are kept."}
          </p>
          <button
            className={secondaryButton}
            disabled={busy || needsReview || !baseRevision || !destination || !revision.writable}
            onClick={() => void run(() => stage(receipt))}
          >
            Retry same staging request
          </button>
          <button className={secondaryButton} disabled={busy} onClick={() => {
            setReceipt(null);
            setNotice("Receipt discarded. This does not undo any rules already staged; review the destination before staging a new batch.");
          }}>Discard receipt</button>
        </div>
      )}
      <section aria-label="Staging destination" className="mt-3 rounded-xs border px-3 py-2 text-sm">
        <p>{destination ? "Changes will be saved to the pending configuration—not activated." : "Pending configuration unavailable. Reload before saving."}</p>
        {destination && <>
          <a href="/config/?tab=diff" target="_blank" rel="noreferrer" className="underline">Review full diff</a>
          <details className="mt-2 text-xs">
            <summary className="cursor-pointer">Destination details</summary>
            <p>Configuration version: {revision.state.serverRevision}</p>
            <p>Pending sections: {destination.changedSections.join(", ") || "none"}</p>
          </details>
        </>}
        {needsReview && destination && <div className="mt-3 grid gap-3"><ConfigDiffBlocks blocks={buildDiffBlocks(destination)} /></div>}
        {revision.revisionNotice(() => refresh({ discard: true }))}
      </section>
      <div className="mt-4 flex flex-wrap gap-2">
        {canEdit && (
          <>
            <button
              className={secondaryButton}
              disabled={
                busy ||
                !!receipt ||
                dataset.state !== "sealed" ||
                Date.parse(dataset.expiresAt) <= now
              }
              onClick={() =>
                void run(async () => {
                  const res = dataOf(await learner.generate(dataset.id));
                  setWithheld(res.withheld);
                  setNotice(
                    `Generation complete: ${res.suggestions?.length ?? 0} certified suggestion(s). Nothing selected.`,
                  );
                  await refresh();
                  await onChanged();
                })
              }
            >
              Generate suggestions
            </button>
            <button
              className={eligible.length ? primaryButton : secondaryButton}
              disabled={
                busy ||
                needsReview ||
                !baseRevision ||
                !destination ||
                !revision.writable ||
                !!receipt ||
                !eligible.length ||
                eligible.length > 128 ||
                ruleCount > 128
              }
              onClick={() =>
                confirm.open({
                  title: "Stage selected suggestions",
                  message: `Save all ${eligible.length} selected suggestion(s), ${ruleCount} monitor rule(s), together? Nothing becomes active until you review and commit the pending configuration.`,
                  confirmLabel: "Stage",
                  onConfirm: () =>
                    void run(() =>
                      stage({
                        requestId: crypto.randomUUID(),
                        selections: eligible.map(({ id, revision }) => ({
                          id,
                          revision,
                        })),
                      }),
                    ),
                })
              }
            >
              Stage {eligible.length} selected
            </button>
          </>
        )}
        <button
          className={secondaryButton}
          disabled={busy}
          onClick={() =>
            void run(async () =>
              setObservations(dataOf(await learner.observations(dataset.id))),
            )
          }
        >
          Inspect service authority
        </button>
      </div>
      {(eligible.length > 128 || ruleCount > 128) && (
        <p role="alert" className="mt-2 text-sm text-(--amber)">
          Select at most 128 suggestions and 128 total rules to save together.
        </p>
      )}
      {withheld && (
        <div className="mt-4">
          <h3 className="text-sm font-semibold">
            Withheld in last generation for this dataset
          </h3>
          <ReasonCounts counts={withheld} />
          {!Object.keys(withheld).length && <p className="text-xs">None.</p>}
        </div>
      )}
      {observations && (
        <section aria-label="Service authority" className="mt-4">
          <h3 className="text-sm font-semibold">Observed service authority</h3>
          <div className="mt-2 overflow-x-auto rounded-xs border">
            <table className="w-full text-left text-xs">
              <thead>
                <tr>
                  {["Service", "Coordinates / roles", "Coverage"].map((h) => (
                    <th className="px-3 py-2" key={h}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(observations.items ?? []).map((o) => (
                  <tr key={o.id} className="border-t">
                    <td className="px-3 py-2">
                      <p>
                        {o.service.clientIp} → {o.service.serverIp}:
                        {o.service.serverPort} ({o.service.transport})
                      </p>
                      <p>
                        {o.service.protocol} · {o.service.direction}
                      </p>
                      <details className="break-all">
                        <summary className="cursor-pointer">Observation ID</summary>
                        <code>{o.id}</code>
                      </details>
                    </td>
                    <td className="px-3 py-2">
                      <p>
                        Role {o.authority.roleCertain ? "certain" : "uncertain"}
                      </p>
                      <p>
                        {o.authority.standardPort
                          ? "Standard service"
                          : "Nonstandard: observation only"}
                      </p>
                      <details className="break-all">
                        <summary className="cursor-pointer">Address and service evidence</summary>
                        <p>{o.service.coordinates} · {o.authority.correlation}</p>
                        <p>{o.authority.roleEvidence}</p>
                        <p>{o.authority.mappingFingerprint}</p>
                      </details>
                    </td>
                    <td className="px-3 py-2">
                      {o.quality.complete ? "Complete" : "Incomplete"} ·{" "}
                      {o.quality.decoded ? "Decoded" : "Undecoded"}
                      <details>
                        <summary className="cursor-pointer">Collection quality details</summary>
                        <p>
                          {[
                            ...(o.quality.loss ?? []),
                            ...(o.quality.conformance ?? []),
                            ...(o.quality.undecoded ?? []),
                          ].join(", ")}
                        </p>
                      </details>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!observations.items?.length && (
            <p className="mt-2 text-sm">No retained observations.</p>
          )}
          {observations.nextCursor && (
            <button
              className={`${secondaryButton} mt-2`}
              disabled={busy}
              onClick={() =>
                void run(async () => {
                  const next = dataOf(
                    await learner.observations(
                      dataset.id,
                      observations.nextCursor,
                    ),
                  );
                  setObservations({
                    ...next,
                    items: [
                      ...(observations.items ?? []),
                      ...(next.items ?? []),
                    ],
                  });
                })
              }
            >
              Load more observations
            </button>
          )}
        </section>
      )}
      {!suggestions && (
        <p className="mt-4 text-sm text-(--text-muted)">
          Suggestions unavailable or loading. Refresh to retry.
        </p>
      )}
      {suggestions && !suggestions.items?.length && (
        <p className="mt-4 text-sm text-(--text-muted)">
          No retained suggestions. Generate from a sealed dataset; unsupported
          relations are withheld, never broadened.
        </p>
      )}
      {(suggestions?.items ?? []).map((s) => (
        <SuggestionReview
          now={now}
          key={`${s.id}:${s.revision}`}
          suggestion={s}
          checked={selected.get(s.id) === s.revision && selectable(s, now)}
          changedSinceSelected={selected.has(s.id) && selected.get(s.id) !== s.revision}
          canEdit={canEdit}
          busy={busy || !!receipt}
          onToggle={() =>
            setSelected((prev) => {
              const next = new Map(prev);
              if (next.get(s.id) === s.revision) next.delete(s.id);
              else next.set(s.id, s.revision);
              return next;
            })
          }
          onReview={(approve, coordinates) =>
            confirm.open({
              title: approve ? "Review suggestion" : "Reject suggestion",
              message: `Record ${approve ? "approval" : "rejection"} of revision ${s.revision}? This does not select or stage any rule.`,
              confirmLabel: approve ? "Review" : "Reject",
              onConfirm: () =>
                void run(async () => {
                  const result = await learner.review(
                    { id: s.id, revision: s.revision },
                    approve,
                    coordinates,
                  );
                  await refresh();
                  dataOf(result);
                  setNotice(
                    approve
                      ? "Review recorded. Select the suggestion separately to stage it."
                      : "Suggestion rejected.",
                  );
                }),
            })
          }
        />
      ))}
      {suggestions?.nextCursor && (
        <button
          className={secondaryButton}
          disabled={busy}
          onClick={() =>
            void run(async () => {
              const next = dataOf(
                await learner.suggestions(dataset.id, suggestions.nextCursor),
              );
              setSuggestions({
                ...next,
                items: [...(suggestions.items ?? []), ...(next.items ?? [])],
              });
            })
          }
        >
          Load more suggestions
        </button>
      )}
    </Card>
  );
}
