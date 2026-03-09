"use client";

import { useEffect, useState } from "react";

import {
  api,
  isAdmin,
  uploadPcap,
  listPcaps,
  type PcapItem,
  type FirewallRule,
} from "../../lib/api";
import { Shell } from "../../components/Shell";

/* ── Types for PCAP analysis responses ─────────────────────────── */

type PcapAnalysisStats = {
  packetCount: number;
  flowCount: number;
  durationSeconds: number;
  protocols: string[];
};

type PcapEventSummary = {
  protocol: string;
  count: number;
};

type PcapGeneratedRule = {
  id: string;
  description: string;
  protocol: string;
  functionCodes?: number[];
  addresses?: string[];
  action: string;
  sourceZones?: string[];
  destZones?: string[];
};

type PcapAnalysisResult = {
  stats: PcapAnalysisStats;
  events: PcapEventSummary[];
  rules: PcapGeneratedRule[];
};

/* ── Helpers ───────────────────────────────────────────────────── */

async function analyzePcapUpload(file: File): Promise<PcapAnalysisResult | null> {
  try {
    const form = new FormData();
    form.append("file", file, file.name);
    const res = await fetch("/api/v1/pcap/analyze", {
      method: "POST",
      credentials: "include",
      body: form,
    });
    if (!res.ok) return null;
    return (await res.json()) as PcapAnalysisResult;
  } catch {
    return null;
  }
}

async function analyzePcapByName(name: string): Promise<PcapAnalysisResult | null> {
  try {
    const res = await fetch(`/api/v1/pcap/analyze/${encodeURIComponent(name)}`, {
      method: "POST",
      credentials: "include",
    });
    if (!res.ok) return null;
    return (await res.json()) as PcapAnalysisResult;
  } catch {
    return null;
  }
}

async function applyGeneratedRules(rules: PcapGeneratedRule[]): Promise<boolean> {
  try {
    const res = await fetch("/api/v1/firewall/ics-rules", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rules }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/* ── Format helpers ────────────────────────────────────────────── */

function fmtDuration(secs: number): string {
  if (secs < 60) return `${secs.toFixed(1)}s`;
  if (secs < 3600) return `${(secs / 60).toFixed(1)}m`;
  return `${(secs / 3600).toFixed(1)}h`;
}

function fmtSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/* ── Page ─────────────────────────────────────────────────────── */

export default function PcapAnalysisPage() {
  const canEdit = isAdmin();
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Upload section
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<PcapAnalysisResult | null>(null);
  const [selectedRules, setSelectedRules] = useState<Set<string>>(new Set());

  // Existing PCAPs
  const [pcaps, setPcaps] = useState<PcapItem[]>([]);
  const [existingAnalyzing, setExistingAnalyzing] = useState<string | null>(null);
  const [existingResult, setExistingResult] = useState<{
    name: string;
    result: PcapAnalysisResult;
  } | null>(null);
  const [existingSelectedRules, setExistingSelectedRules] = useState<Set<string>>(new Set());

  async function refreshPcaps() {
    const list = await listPcaps();
    setPcaps(list);
  }

  useEffect(() => {
    refreshPcaps();
  }, []);

  async function handleAnalyzeUpload() {
    if (!uploadFile) return;
    setError(null);
    setSuccess(null);
    setAnalyzing(true);
    setResult(null);
    const res = await analyzePcapUpload(uploadFile);
    setAnalyzing(false);
    if (!res) {
      setError("Failed to analyze PCAP file.");
      return;
    }
    setResult(res);
    setSelectedRules(new Set(res.rules.map((r) => r.id)));
    refreshPcaps();
  }

  async function handleAnalyzeExisting(name: string) {
    setError(null);
    setSuccess(null);
    setExistingAnalyzing(name);
    setExistingResult(null);
    const res = await analyzePcapByName(name);
    setExistingAnalyzing(null);
    if (!res) {
      setError(`Failed to analyze PCAP: ${name}`);
      return;
    }
    setExistingResult({ name, result: res });
    setExistingSelectedRules(new Set(res.rules.map((r) => r.id)));
  }

  async function handleApplyRules(
    rules: PcapGeneratedRule[],
    selected: Set<string>,
  ) {
    setError(null);
    setSuccess(null);
    const toApply = rules.filter((r) => selected.has(r.id));
    if (toApply.length === 0) {
      setError("No rules selected.");
      return;
    }
    const ok = await applyGeneratedRules(toApply);
    if (!ok) {
      setError("Failed to apply rules.");
      return;
    }
    setSuccess(`${toApply.length} rule(s) applied successfully.`);
  }

  return (
    <Shell
      title="PCAP Analysis"
      actions={
        <button
          onClick={refreshPcaps}
          className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
        >
          Refresh
        </button>
      }
    >
      {error && (
        <div className="mb-4 rounded-xl border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-amber">
          {error}
        </div>
      )}
      {success && (
        <div className="mb-4 rounded-xl border border-mint/30 bg-mint/10 px-4 py-3 text-sm text-mint">
          {success}
        </div>
      )}

      {/* ── Section 1: PCAP Upload & Analysis ──────────────────── */}
      <div className="mb-6 rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
        <h2 className="mb-1 text-xs uppercase tracking-[0.2em] text-slate-300">
          Upload & Analyze PCAP
        </h2>
        <p className="mb-4 text-sm text-slate-400">
          Upload a .pcap file for DPI analysis. The engine will extract flows,
          detect ICS protocols, and generate suggested firewall rules.
        </p>

        <div className="flex items-center gap-3">
          <label className="flex-1">
            <input
              type="file"
              accept=".pcap,.pcapng"
              onChange={(e) => setUploadFile(e.target.files?.[0] ?? null)}
              className="block w-full text-sm text-slate-200 file:mr-3 file:rounded-lg file:border-0 file:bg-white/10 file:px-3 file:py-2 file:text-sm file:text-slate-200 hover:file:bg-white/20"
            />
          </label>
          <button
            onClick={handleAnalyzeUpload}
            disabled={!uploadFile || analyzing}
            className="rounded-lg bg-mint/20 px-4 py-2 text-sm text-mint hover:bg-mint/30 disabled:opacity-40"
          >
            {analyzing ? "Analyzing..." : "Analyze"}
          </button>
        </div>

        {result && (
          <AnalysisResults
            result={result}
            selectedRules={selectedRules}
            onToggleRule={(id) =>
              setSelectedRules((prev) => {
                const next = new Set(prev);
                next.has(id) ? next.delete(id) : next.add(id);
                return next;
              })
            }
            onToggleAll={() =>
              setSelectedRules((prev) =>
                prev.size === result.rules.length
                  ? new Set()
                  : new Set(result.rules.map((r) => r.id)),
              )
            }
            onApply={() => handleApplyRules(result.rules, selectedRules)}
            canEdit={canEdit}
          />
        )}
      </div>

      {/* ── Section 2: Existing PCAPs ──────────────────────────── */}
      <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
        <h2 className="mb-1 text-xs uppercase tracking-[0.2em] text-slate-300">
          Existing PCAP Files
        </h2>
        <p className="mb-4 text-sm text-slate-400">
          Previously uploaded or captured PCAPs. Click Analyze to extract
          protocols and generate rules.
        </p>

        {pcaps.length === 0 ? (
          <div className="text-sm text-slate-400">No PCAP files found.</div>
        ) : (
          <div className="overflow-hidden rounded-xl border border-white/10">
            <table className="w-full text-sm">
              <thead className="bg-black/30 text-left text-xs uppercase tracking-wide text-slate-300">
                <tr>
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3">Interface</th>
                  <th className="px-4 py-3">Size</th>
                  <th className="px-4 py-3">Created</th>
                  <th className="px-4 py-3">Tags</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {pcaps.map((p) => (
                  <tr key={p.name} className="border-t border-white/5">
                    <td className="px-4 py-3 font-mono text-xs text-white">
                      {p.name}
                    </td>
                    <td className="px-4 py-3 text-slate-200">
                      {p.interface || "-"}
                    </td>
                    <td className="px-4 py-3 text-slate-200">
                      {fmtSize(p.sizeBytes)}
                    </td>
                    <td className="px-4 py-3 text-slate-200">
                      {new Date(p.createdAt).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      {(p.tags ?? []).length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {p.tags!.map((t) => (
                            <span
                              key={t}
                              className="rounded-full bg-white/10 px-2 py-0.5 text-xs text-slate-200"
                            >
                              {t}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-xs text-slate-400">-</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => handleAnalyzeExisting(p.name)}
                        disabled={existingAnalyzing === p.name}
                        className="rounded-md bg-mint/20 px-2 py-1 text-xs text-mint hover:bg-mint/30 disabled:opacity-40"
                      >
                        {existingAnalyzing === p.name
                          ? "Analyzing..."
                          : "Analyze"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {existingResult && (
          <div className="mt-4">
            <div className="mb-2 text-sm text-slate-200">
              Results for{" "}
              <span className="font-mono text-mint">{existingResult.name}</span>
            </div>
            <AnalysisResults
              result={existingResult.result}
              selectedRules={existingSelectedRules}
              onToggleRule={(id) =>
                setExistingSelectedRules((prev) => {
                  const next = new Set(prev);
                  next.has(id) ? next.delete(id) : next.add(id);
                  return next;
                })
              }
              onToggleAll={() =>
                setExistingSelectedRules((prev) =>
                  prev.size === existingResult.result.rules.length
                    ? new Set()
                    : new Set(existingResult.result.rules.map((r) => r.id)),
                )
              }
              onApply={() =>
                handleApplyRules(
                  existingResult.result.rules,
                  existingSelectedRules,
                )
              }
              canEdit={canEdit}
            />
          </div>
        )}
      </div>
    </Shell>
  );
}

/* ── Analysis Results Component ────────────────────────────────── */

function AnalysisResults({
  result,
  selectedRules,
  onToggleRule,
  onToggleAll,
  onApply,
  canEdit,
}: {
  result: PcapAnalysisResult;
  selectedRules: Set<string>;
  onToggleRule: (id: string) => void;
  onToggleAll: () => void;
  onApply: () => void;
  canEdit: boolean;
}) {
  return (
    <div className="mt-4 space-y-4">
      {/* Stats summary */}
      <div className="grid gap-3 md:grid-cols-4">
        <StatCard label="Packets" value={result.stats.packetCount.toLocaleString()} />
        <StatCard label="Flows" value={result.stats.flowCount.toLocaleString()} />
        <StatCard label="Duration" value={fmtDuration(result.stats.durationSeconds)} />
        <div className="rounded-xl border border-white/10 bg-black/30 p-3">
          <div className="text-xs uppercase tracking-wide text-slate-400">
            Protocols
          </div>
          <div className="mt-1 flex flex-wrap gap-1">
            {result.stats.protocols.map((p) => (
              <span
                key={p}
                className="rounded-full bg-white/10 px-2 py-0.5 text-xs text-slate-200"
              >
                {p}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Event summary table */}
      {result.events.length > 0 && (
        <div className="overflow-hidden rounded-xl border border-white/10">
          <table className="w-full text-sm">
            <thead className="bg-black/30 text-left text-xs uppercase tracking-wide text-slate-300">
              <tr>
                <th className="px-4 py-2">Protocol</th>
                <th className="px-4 py-2">Event Count</th>
              </tr>
            </thead>
            <tbody>
              {result.events.map((e) => (
                <tr key={e.protocol} className="border-t border-white/5">
                  <td className="px-4 py-2 text-slate-200">{e.protocol}</td>
                  <td className="px-4 py-2 font-mono text-xs text-slate-200">
                    {e.count.toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Generated rules */}
      {result.rules.length > 0 && (
        <>
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">
              Generated Rules ({result.rules.length})
            </h3>
            <div className="flex items-center gap-2">
              <button
                onClick={onToggleAll}
                className="rounded-md bg-white/5 px-2 py-1 text-xs text-slate-200 hover:bg-white/10"
              >
                {selectedRules.size === result.rules.length
                  ? "Deselect All"
                  : "Select All"}
              </button>
              {canEdit && (
                <button
                  onClick={onApply}
                  disabled={selectedRules.size === 0}
                  className="rounded-lg bg-mint/20 px-3 py-1.5 text-sm text-mint hover:bg-mint/30 disabled:opacity-40"
                >
                  Apply {selectedRules.size} Rule(s)
                </button>
              )}
            </div>
          </div>
          <div className="overflow-hidden rounded-xl border border-white/10">
            <table className="w-full text-sm">
              <thead className="bg-black/30 text-left text-xs uppercase tracking-wide text-slate-300">
                <tr>
                  <th className="px-4 py-2 w-8"></th>
                  <th className="px-4 py-2">ID</th>
                  <th className="px-4 py-2">Description</th>
                  <th className="px-4 py-2">Protocol</th>
                  <th className="px-4 py-2">Function Codes</th>
                  <th className="px-4 py-2">Addresses</th>
                  <th className="px-4 py-2">Action</th>
                </tr>
              </thead>
              <tbody>
                {result.rules.map((r) => (
                  <tr key={r.id} className="border-t border-white/5">
                    <td className="px-4 py-2">
                      <input
                        type="checkbox"
                        checked={selectedRules.has(r.id)}
                        onChange={() => onToggleRule(r.id)}
                        className="h-4 w-4 rounded border-white/20 bg-black/30"
                      />
                    </td>
                    <td className="px-4 py-2 font-mono text-xs text-white">
                      {r.id}
                    </td>
                    <td className="px-4 py-2 text-slate-200">
                      {r.description || "-"}
                    </td>
                    <td className="px-4 py-2">
                      <span className="rounded-full bg-white/10 px-2 py-0.5 text-xs text-slate-200">
                        {r.protocol}
                      </span>
                    </td>
                    <td className="px-4 py-2 font-mono text-xs text-slate-200">
                      {(r.functionCodes ?? []).join(", ") || "*"}
                    </td>
                    <td className="px-4 py-2 font-mono text-xs text-slate-200">
                      {(r.addresses ?? []).join(", ") || "*"}
                    </td>
                    <td className="px-4 py-2">
                      <span
                        className={`rounded-full px-2 py-0.5 text-xs ${
                          r.action === "ALLOW"
                            ? "bg-mint/20 text-mint"
                            : "bg-red-500/20 text-red-400"
                        }`}
                      >
                        {r.action}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {result.rules.length === 0 && (
        <div className="text-sm text-slate-400">
          No rules generated from this PCAP. The capture may not contain
          recognizable ICS protocol traffic.
        </div>
      )}
    </div>
  );
}

/* ── Stat Card ─────────────────────────────────────────────────── */

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-white/10 bg-black/30 p-3">
      <div className="text-xs uppercase tracking-wide text-slate-400">
        {label}
      </div>
      <div className="mt-1 text-lg font-semibold text-white">{value}</div>
    </div>
  );
}
