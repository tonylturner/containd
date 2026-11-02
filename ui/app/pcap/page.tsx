"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useAsyncRefresh } from "../../hooks/useAsyncRefresh";
import { isAdmin, listPcaps, type PcapItem } from "../../lib/api";
import {
  analyzeUpload,
  learner,
  type LearnCounters,
  type LearnDataset,
  type LearnPage,
  type LearnWatch,
  type PcapImportResult,
} from "../../lib/api-learn";
import { useConfigRefresh } from "../../lib/use-config-refresh";
import { Shell } from "../../components/Shell";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import { Card } from "../../components/Card";
import { IdentificationTable } from "./identifications";
import { DatasetList } from "./dataset-list";
import { DatasetReview, dataOf, ReasonCounts } from "./dataset-review";
import { LearnerSteps } from "./learner-steps";
import { primaryButton, secondaryButton } from "./suggestion-review";
import { formatEvidenceTime } from "./evidence-time";
import styles from "./collection-tabs.module.css";

export default function PcapAnalysisPage() {
  const canEdit = isAdmin();
  const confirm = useConfirm();
  const [notice, setNotice] = useState("");
  const [datasets, setDatasets] = useState<LearnPage<LearnDataset> | null>(
    null,
  );
  const [watches, setWatches] = useState<LearnPage<LearnWatch> | null>(null);
  const [counters, setCounters] = useState<LearnCounters | null>(null);
  const [pcaps, setPcaps] = useState<PcapItem[]>([]);
  const [chosen, setChosen] = useState<LearnDataset | null>(null);
  const [imported, setImported] = useState<PcapImportResult | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [collectTab, setCollectTab] = useState<"import" | "watch">("import");
  const watchToInspect = useRef<string | null>(null);
  const [duration, setDuration] = useState("3600");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (collectTab !== "watch" || !watchToInspect.current) return;
    const row = document.getElementById(`watch-${watchToInspect.current}`);
    watchToInspect.current = null;
    row?.focus({ preventScroll: true });
    row?.scrollIntoView({ block: "center" });
  }, [collectTab]);

  const { refresh } = useAsyncRefresh(useCallback(async () => {
    try {
      const [ds, ws, cs, ps] = await Promise.all([
        learner.datasets(),
        learner.watches(),
        learner.counters(),
        listPcaps(),
      ]);
      const fresh = dataOf(ds);
      setDatasets(fresh);
      setWatches(dataOf(ws));
      setCounters(dataOf(cs));
      setPcaps(ps);
      setNow(Date.now());
      setChosen((prev) =>
        prev
          ? ((fresh.items ?? []).find((d) => d.id === prev.id) ?? null)
          : null,
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setDatasets(null);
      setWatches(null);
      setCounters(null);
    }
  }, []));
  useEffect(() => {
    const timer = setInterval(() => void refresh(), 10000);
    return () => clearInterval(timer);
  }, [refresh]);
  useConfigRefresh(refresh);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
      setNow(Date.now());
    }
  }
  async function showImport(result: PcapImportResult) {
    setImported(result);
    await refresh();
    setChosen(result.dataset);
  }
  const active = (watches?.items ?? []).filter(
    (w) => !w.stoppedAt && Date.parse(w.deadline) > now,
  );
  const abnormalStops = (watches?.items ?? []).filter(
    (w) => w.stoppedAt && w.stopReason && !["operator", "deadline"].includes(w.stopReason),
  );
  const seconds = Number(duration);
  return (
    <Shell
      title="PCAP Analysis"
      actions={
        <button
          className={secondaryButton}
          disabled={busy}
          onClick={() => void run(refresh)}
        >
          Refresh
        </button>
      }
    >
      <p className="mb-4 max-w-prose text-sm text-(--text-muted)">
        Import a capture or watch live traffic, generate checked rule suggestions,
        then review and save selected versions. Learning never changes active
        policy. Review the changes and commit them from Configuration to apply them.
      </p>
      {!canEdit && (
        <p className="mb-4 text-sm">
          Read-only viewer. An administrator imports, generates, reviews and
          stages suggestions.
        </p>
      )}
      {error && (
        <p
          role="alert"
          className="mb-4 break-words rounded-xs border border-red/30 bg-red/10 p-3 text-sm text-(--red)"
        >
          {error}
        </p>
      )}
      {!chosen && <LearnerSteps hasDataset={false} generateReason="Open a dataset after collecting evidence." reviewReason="Open a dataset to inspect suggestions." stageReason="Review and select eligible suggestions first." />}
      <section id="learner-collect" tabIndex={-1} aria-label="Collect evidence" className="min-w-0">
        <h2 className="mb-3 text-lg font-semibold">1 Collect</h2>
        <div className="mb-4 flex flex-wrap gap-2" role="tablist" aria-label="Collection source">
          {([['import', 'Import capture'], ['watch', 'Watch live']] as const).map(([tab, label]) => (
            <button key={tab} id={`collect-tab-${tab}`} role="tab" aria-selected={collectTab === tab} aria-controls={`collect-panel-${tab}`}
              tabIndex={collectTab === tab ? 0 : -1}
              className={styles.tab}
              onKeyDown={(event) => {
                if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
                event.preventDefault();
                const next = event.key === "Home" ? "import" : event.key === "End" ? "watch" : tab === "import" ? "watch" : "import";
                setCollectTab(next);
                document.getElementById(`collect-tab-${next}`)?.focus();
              }}
              onClick={() => setCollectTab(tab)}>{label}</button>
          ))}
        </div>
        <div id="collect-panel-import" role="tabpanel" aria-labelledby="collect-tab-import" hidden={collectTab !== "import"}>
          {canEdit && (
            <Card title="Upload & Analyze PCAP" className="mb-6">
              <p className="mb-3 text-sm text-(--text-muted)">
                Analyze imports evidence only; Generate is a separate action.
                Classic .pcap, up to 64 MiB. PCAPng is not supported.
              </p>
              <div className="flex flex-wrap items-center gap-3">
                <input
                  aria-label="PCAP file"
                  type="file"
                  accept=".pcap"
                  className="min-w-0 max-w-full flex-1 text-sm"
                  disabled={busy}
                  onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                />
                <button
                  className={primaryButton}
                  disabled={busy || !file}
                  onClick={() =>
                    void run(async () => {
                      if (!file) return;
                      if (file.size > 64 * 1024 * 1024)
                        throw new Error("PCAP exceeds the 64 MiB import limit.");
                      await showImport(dataOf(await analyzeUpload(file)));
                    })
                  }
                >
                  {busy ? "Working…" : "Analyze"}
                </button>
              </div>
            </Card>
          )}
          {canEdit && (
            <Card title="Existing PCAP Files" className="mb-6">
              <p className="mb-3 text-sm text-(--text-muted)">
                Analyze a named capture to import a dataset; no rules are generated
                automatically.
              </p>
              {!pcaps.length && <p className="text-sm">No PCAP files found.</p>}
              <ul className="space-y-2">
                {pcaps.map((p) => (
                  <li
                    key={p.name}
                    className="flex flex-wrap items-center justify-between gap-3 border-t pt-2"
                  >
                    <span className="min-w-0 break-all font-mono text-xs">
                      {p.name} · {p.sizeBytes.toLocaleString()} bytes
                    </span>
                    <button
                      className={secondaryButton}
                      disabled={busy}
                      onClick={() =>
                        void run(async () =>
                          showImport(dataOf(await learner.analyze(p.name))),
                        )
                      }
                    >
                      Analyze
                    </button>
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </div>
        <div id="collect-panel-watch" role="tabpanel" aria-labelledby="collect-tab-watch" hidden={collectTab !== "watch"}>
          <Card title="Live watch" className="mb-6">
            <p className="mb-3 text-sm text-(--text-muted)">
              One active watch. Default 1 hour, maximum 24 hours. Stopping finishes this
              collection so suggestions can be generated and reviewed. Restart never resumes
              collection; rule modes do not start a watch.
            </p>
            {canEdit && (
              <div className="mb-4 flex flex-wrap items-center gap-3">
                <label className="text-sm">
                  Duration (seconds)
                  <input
                    className="ml-2 w-28 rounded-xs border bg-(--surface2) px-2 py-1.5"
                    type="number"
                    min="1"
                    max="86400"
                    step="1"
                    value={duration}
                    disabled={busy}
                    onChange={(e) => setDuration(e.target.value)}
                  />
                </label>
                <button
                  className={primaryButton}
                  disabled={
                    busy ||
                    !watches ||
                    !!active.length ||
                    !Number.isInteger(seconds) ||
                    seconds < 1 ||
                    seconds > 86400
                  }
                  onClick={() =>
                    void run(async () => {
                      const res = await learner.start(seconds);
                      await refresh();
                      const watch = dataOf(res);
                      const ds = dataOf(await learner.datasets());
                      setDatasets(ds);
                      setChosen(
                        (ds.items ?? []).find((d) => d.id === watch.datasetId) ??
                        null,
                      );
                    })
                  }
                >
                  Start watch
                </button>
              </div>
            )}
            {!watches && (
              <p className="text-sm">Watch status unavailable or loading.</p>
            )}
            {watches && !watches.items?.length && (
              <p className="text-sm">No live watches.</p>
            )}
            <ul className="space-y-2">
              {(watches?.items ?? []).map((w) => {
                const running = !w.stoppedAt && Date.parse(w.deadline) > now;
                return (
                  <li
                    key={w.id}
                    id={`watch-${w.id}`}
                    tabIndex={-1}
                    className="flex flex-wrap items-center justify-between gap-2 border-t pt-2 text-xs"
                  >
                    <div className="min-w-0">
                      <p className="break-all font-mono">{w.id}</p>
                      <p>
                        {running ? "Collecting" : "Stopped"} · deadline{" "}
                        {formatEvidenceTime(w.deadline)}{" "}
                        {w.stopReason && `· ${w.stopReason}`}
                      </p>
                      <p className="break-all text-(--text-muted)">
                        Dataset {w.datasetId}
                      </p>
                    </div>
                    {canEdit && running && (
                      <button
                        className={secondaryButton}
                        disabled={busy}
                        onClick={() =>
                          void run(async () => {
                            const res = await learner.stop(w.id);
                            await refresh();
                            dataOf(res);
                          })
                        }
                      >
                        Stop watch
                      </button>
                    )}
                  </li>
                );
              })}
            </ul>
            {watches?.nextCursor && (
              <button
                className={`${secondaryButton} mt-2`}
                disabled={busy}
                onClick={() =>
                  void run(async () => {
                    const next = dataOf(await learner.watches(watches.nextCursor));
                    setWatches({
                      ...next,
                      items: [...(watches.items ?? []), ...(next.items ?? [])],
                    });
                  })
                }
              >
                Load more watches
              </button>
            )}
          </Card>
        </div>
      </section>
      {collectTab !== "watch" && active.length > 0 && <p className="mb-4 text-sm text-(--amber)">Live watch collecting · {active.length} active. Open Watch live to inspect or stop collection.</p>}
      {!watches && collectTab !== "watch" && <p className="mb-4 text-sm">Watch status unavailable or loading.</p>}
      {collectTab !== "watch" && abnormalStops.length > 0 && (
        <section aria-label="Abnormally stopped watches" role="status" className="mb-4 space-y-2 break-words text-sm text-(--amber)">
          <p>Live collection stopped unexpectedly. Review the cause and collection limitations before using its evidence.</p>
          {abnormalStops.map((watch) => (
            <p key={watch.id}>
              <a
                className="break-all underline"
                href={`#watch-${watch.id}`}
                onClick={() => {
                  watchToInspect.current = watch.id;
                  setCollectTab("watch");
                }}
              >
                Inspect watch {watch.id}
              </a>
              {" · "}{watch.stopReason} · stopped {formatEvidenceTime(watch.stoppedAt)}
            </p>
          ))}
        </section>
      )}
      {chosen && (
        <DatasetReview now={now} key={chosen.id} dataset={chosen} canEdit={canEdit} onChanged={refresh} />
      )}
      <ConfirmDialog {...confirm.props} />
      {notice && <p role="status" className="mb-3 text-sm">{notice}</p>}
      <Card title="Evidence datasets" className="mb-6">
        <p className="mb-3 text-xs text-(--text-muted)">Evidence expires after 7 days. Removing evidence at capacity invalidates the checks that depend on it. Dataset deletion is immediate and cannot be undone; staged rules and original PCAP files remain.</p>
        <details className="mb-3 text-xs text-(--text-muted)">
          <summary className="cursor-pointer">Saved evidence limits</summary>
          <p>Store ceilings: 32 datasets, 100,000 records, 128 MiB normalized evidence; 256 KiB / 4,096 objects per parent. Evictions invalidate dependent proofs.</p>
        </details>
        {!datasets && (
          <p className="text-sm">
            Datasets unavailable or loading. Refresh to retry.
          </p>
        )}
        {datasets && !datasets.items?.length && (
          <p className="text-sm">
            No retained datasets. Import a PCAP or start a live watch.
          </p>
        )}
        {!!datasets?.items?.length && (
          <DatasetList
            datasets={datasets.items}
            selectedId={chosen?.id}
            onOpen={setChosen}
            busy={busy}
            onDelete={canEdit ? dataset => confirm.open({
              title: "Delete learner dataset?",
              message: `Immediately delete dataset ${dataset.id}, its observations and dependent suggestions/proofs? This cannot be undone. Already staged rules and the original PCAP file are not deleted. Stop an active watch before deleting its dataset. No commit is required.`,
              confirmLabel: "Delete dataset",
              variant: "danger",
              onConfirm: () => void run(async () => {
                dataOf(await learner.deleteDataset(dataset.id));
                setChosen(previous => previous?.id === dataset.id ? null : previous);
                setImported(previous => previous?.dataset.id === dataset.id ? null : previous);
                setNotice(`Dataset ${dataset.id} deleted immediately. Staged rules and original PCAP files are unchanged.`);
                await refresh();
              }),
            }) : undefined}
          />
        )}
        {datasets?.nextCursor && (
          <button
            className={`${secondaryButton} mt-2`}
            disabled={busy}
            onClick={() =>
              void run(async () => {
                const next = dataOf(
                  await learner.datasets(datasets.nextCursor),
                );
                setDatasets({
                  ...next,
                  items: [...(datasets.items ?? []), ...(next.items ?? [])],
                });
              })
            }
          >
            Load more datasets
          </button>
        )}
        {counters && (
          <details className="mt-4 text-xs">
            <summary className="cursor-pointer">
              Store-wide admission and withheld counts
              {(counters.lostBatches > 0 || counters.rejectedParents > 0
                || counters.evictedRecords > 0 || counters.expiredRecords > 0) && (
                  <span className="ml-2 text-(--amber)">
                    Evidence removed or not retained · lost batches {counters.lostBatches}
                    {" · rejected parents "}{counters.rejectedParents}
                    {" · evicted records "}{counters.evictedRecords}
                    {" · expired records "}{counters.expiredRecords}
                  </span>
                )}
            </summary>
            <p className="mt-2">
              {counters.records} records / {counters.bytes} bytes · evicted{" "}
              {counters.evictedRecords} records / {counters.evictedBytes} bytes
              · expired {counters.expiredRecords} · lost batches{" "}
              {counters.lostBatches} · rejected parents{" "}
              {counters.rejectedParents}
            </p>
            <p className="mt-2">
              Durable totals, not per-dataset counts. Last-generation dataset
              reasons appear in its review below.
            </p>
            <ReasonCounts counts={counters.withheld} />
          </details>
        )}
      </Card>
      {imported && (
        <Card title="Last import statistics" className="mb-6">
          <p className="mb-2 break-all text-xs">
            Dataset {imported.dataset.id}
          </p>
          <p className="mb-2 text-sm">
            {imported.stats.packetCount ?? 0} packets ·{" "}
            {imported.stats.byteCount ?? 0} bytes ·{" "}
            {imported.stats.flows?.length ?? 0} flows ·{" "}
            {((imported.stats.duration ?? 0) / 1e9).toFixed(1)} seconds
          </p>
          <p className="mb-2 text-xs">
            Protocols:{" "}
            {Object.entries(imported.stats.protocols ?? {})
              .map(([p, n]) => `${p}: ${n}`)
              .join(", ") || "none"}
          </p>
          {imported.stats.truncated && (
            <p role="status" className="mb-2 text-sm text-(--amber)">
              Capture truncated: missing records may leave incomplete evidence.
            </p>
          )}
          {imported.stats.displayTruncated && (
            <p role="status" className="mb-2 text-sm text-(--amber)">
              Only the display is shortened; analysis still uses all retained evidence.
            </p>
          )}
          <IdentificationTable
            identifications={imported.stats.identifications ?? []}
          />
        </Card>
      )}
    </Shell>
  );
}
