 "use client";

import { useEffect, useMemo, useState } from "react";

import { api, type ConfigBundle } from "../../lib/api";
import { Shell } from "../../components/Shell";

type Tab = "running" | "candidate" | "diff";

export default function ConfigPage() {
  const [tab, setTab] = useState<Tab>("diff");
  const [running, setRunning] = useState<ConfigBundle | null>(null);
  const [candidate, setCandidate] = useState<ConfigBundle | null>(null);
  const [candidateText, setCandidateText] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [ttlSeconds, setTtlSeconds] = useState("60");

  async function refresh() {
    const d = await api.diffConfig();
    setRunning(d?.running ?? null);
    setCandidate(d?.candidate ?? null);
    setCandidateText(
      JSON.stringify(d?.candidate ?? d?.running ?? {}, null, 2),
    );
  }

  useEffect(() => {
    refresh();
  }, []);

  async function saveCandidate() {
    setStatus(null);
    try {
      const parsed = JSON.parse(candidateText) as ConfigBundle;
      const res = await api.setCandidateConfig(parsed);
      if (!res) {
        setStatus("Failed to save candidate.");
        return;
      }
      setStatus("Candidate saved.");
      refresh();
    } catch (e) {
      setStatus("Invalid JSON.");
    }
  }

  async function doCommit() {
    setStatus(null);
    const res = await api.commit();
    setStatus(res ? "Committed." : "Commit failed.");
    refresh();
  }

  async function doCommitConfirmed() {
    setStatus(null);
    const ttl = Number(ttlSeconds);
    const res = await api.commitConfirmed(
      Number.isFinite(ttl) && ttl > 0 ? ttl : undefined,
    );
    setStatus(res ? "Commit-confirmed started." : "Commit-confirmed failed.");
    refresh();
  }

  async function doConfirm() {
    setStatus(null);
    const res = await api.confirmCommit();
    setStatus(res ? "Commit confirmed." : "Confirm failed.");
    refresh();
  }

  async function doRollback() {
    setStatus(null);
    const res = await api.rollback();
    setStatus(res ? "Rolled back." : "Rollback failed.");
    refresh();
  }

  const runningText = useMemo(
    () => JSON.stringify(running ?? {}, null, 2),
    [running],
  );
  const diffText = useMemo(
    () =>
      JSON.stringify(
        { running: running ?? null, candidate: candidate ?? null },
        null,
        2,
      ),
    [running, candidate],
  );

  return (
    <Shell
      title="Config Lifecycle"
      actions={
        <button
          onClick={refresh}
          className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
        >
          Refresh
        </button>
      }
    >
      <div className="mb-4 flex flex-wrap gap-2">
        {(["diff", "running", "candidate"] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={
              tab === t
                ? "rounded-lg bg-white/10 px-3 py-1.5 text-sm text-white"
                : "rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
            }
          >
            {t}
          </button>
        ))}
      </div>

      {status && (
        <div className="mb-4 rounded-xl border border-white/10 bg-black/30 px-4 py-3 text-sm text-slate-200">
          {status}
        </div>
      )}

      {tab === "candidate" && (
        <div className="rounded-2xl border border-white/10 bg-white/5 p-4 shadow-lg backdrop-blur">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">
              Candidate JSON
            </h2>
            <button
              onClick={saveCandidate}
              className="rounded-lg bg-mint/20 px-3 py-1.5 text-sm font-semibold text-mint hover:bg-mint/30"
            >
              Save candidate
            </button>
          </div>
          <textarea
            value={candidateText}
            onChange={(e) => setCandidateText(e.target.value)}
            rows={22}
            className="w-full rounded-lg border border-white/10 bg-black/40 p-3 font-mono text-xs text-white"
          />
        </div>
      )}

      {tab === "running" && (
        <pre className="rounded-2xl border border-white/10 bg-black/40 p-4 text-xs text-slate-100 shadow-lg backdrop-blur">
{runningText}
        </pre>
      )}

      {tab === "diff" && (
        <pre className="rounded-2xl border border-white/10 bg-black/40 p-4 text-xs text-slate-100 shadow-lg backdrop-blur">
{diffText}
        </pre>
      )}

      <div className="mt-6 flex flex-wrap items-center gap-2 rounded-2xl border border-white/10 bg-white/5 p-4 shadow-lg backdrop-blur">
        <button
          onClick={doCommit}
          className="rounded-lg bg-mint/20 px-3 py-1.5 text-sm font-semibold text-mint hover:bg-mint/30"
        >
          Commit
        </button>
        <div className="flex items-center gap-2">
          <button
            onClick={doCommitConfirmed}
            className="rounded-lg bg-white/10 px-3 py-1.5 text-sm text-white hover:bg-white/20"
          >
            Commit-confirmed
          </button>
          <input
            value={ttlSeconds}
            onChange={(e) => setTtlSeconds(e.target.value)}
            className="w-20 rounded-md border border-white/10 bg-black/40 px-2 py-1 text-sm text-white"
          />
          <span className="text-xs text-slate-300">seconds</span>
        </div>
        <button
          onClick={doConfirm}
          className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
        >
          Confirm
        </button>
        <button
          onClick={doRollback}
          className="rounded-lg bg-amber/20 px-3 py-1.5 text-sm font-semibold text-amber hover:bg-amber/30"
        >
          Rollback
        </button>
      </div>
    </Shell>
  );
}

