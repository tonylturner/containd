"use client";

import { useEffect, useState } from "react";

import {
  api,
  isAdmin,
  uploadPcap,
  listPcaps,
  type PcapItem,
} from "../../lib/api";
import { Shell } from "../../components/Shell";
import { Card } from "../../components/Card";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";

/* -- Types matching backend PolicyAnalysis / AnalysisResult -- */

type AnalysisStats = {
  events: unknown[];
  flows: FlowSummary[];
  protocols: Record<string, number>;
  duration: number; // nanoseconds
  packetCount: number;
  byteCount: number;
};

type FlowSummary = {
  key: string;
  protocol: string;
  packets: number;
  bytes: number;
  events: number;
  firstSeen: string;
  lastSeen: string;
};

type PolicyRule = {
  id: string;
  description?: string;
  sourceZones?: string[];
  destZones?: string[];
  sources?: string[];
  destinations?: string[];
  protocols?: { name: string; port?: string }[];
  ics?: {
    protocol?: string;
    functionCodes?: number[];
    unitIDs?: number[];
    addresses?: string[];
    direction?: string;
  };
  action: string;
};

type LearnedProfile = {
  protocol: string;
  sourceIP: string;
  destIP: string;
  unitIDs?: Record<string, boolean>;
  functionCodes?: Record<string, boolean>;
  addresses?: Record<string, boolean>;
  readSeen: boolean;
  writeSeen: boolean;
  packetCount: number;
};

type PolicyAnalysis = {
  rules: PolicyRule[];
  profiles: LearnedProfile[];
  stats: AnalysisStats;
  eventSummary: Record<string, number>;
};

/* -- Helpers -- */

async function analyzePcapUpload(file: File): Promise<PolicyAnalysis | null> {
  try {
    const form = new FormData();
    form.append("file", file, file.name);
    const res = await fetch("/api/v1/pcap/analyze", {
      method: "POST",
      credentials: "include",
      body: form,
    });
    if (!res.ok) return null;
    return (await res.json()) as PolicyAnalysis;
  } catch {
    return null;
  }
}

async function analyzePcapByName(name: string): Promise<PolicyAnalysis | null> {
  try {
    const res = await fetch(`/api/v1/pcap/analyze/${encodeURIComponent(name)}`, {
      method: "POST",
      credentials: "include",
    });
    if (!res.ok) return null;
    return (await res.json()) as PolicyAnalysis;
  } catch {
    return null;
  }
}

async function applyGeneratedRules(rules: PolicyRule[]): Promise<boolean> {
  try {
    const res = await fetch("/api/v1/firewall/rules", {
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

/* -- Format helpers -- */

function fmtDuration(nanos: number): string {
  const secs = nanos / 1e9;
  if (secs < 60) return `${secs.toFixed(1)}s`;
  if (secs < 3600) return `${(secs / 60).toFixed(1)}m`;
  return `${(secs / 3600).toFixed(1)}h`;
}

function fmtSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/* -- Page -- */

export default function PcapAnalysisPage() {
  const canEdit = isAdmin();
  const confirm = useConfirm();
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Upload section
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<PolicyAnalysis | null>(null);
  const [selectedRules, setSelectedRules] = useState<Set<string>>(new Set());

  // Existing PCAPs
  const [pcaps, setPcaps] = useState<PcapItem[]>([]);
  const [existingAnalyzing, setExistingAnalyzing] = useState<string | null>(null);
  const [existingResult, setExistingResult] = useState<{
    name: string;
    result: PolicyAnalysis;
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
    rules: PolicyRule[],
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
          className="rounded-lg border border-white/[0.08] bg-white/[0.04] px-3 py-1.5 text-sm text-slate-200 transition-ui hover:bg-white/[0.08]"
        >
          Refresh
        </button>
      }
    >
      <ConfirmDialog {...confirm.props} />
      {error && (
        <div className="mb-4 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}
      {success && (
        <div className="mb-4 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400">
          {success}
        </div>
      )}

      {/* -- Section 1: PCAP Upload & Analysis -- */}
      <Card title="Upload & Analyze PCAP" padding="lg" className="mb-6">
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
              className="block w-full text-sm text-slate-200 file:mr-3 file:rounded-lg file:border-0 file:bg-white/[0.08] file:px-3 file:py-2 file:text-sm file:text-slate-200 hover:file:bg-white/[0.12]"
            />
          </label>
          <button
            onClick={handleAnalyzeUpload}
            disabled={!uploadFile || analyzing}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 transition-ui disabled:opacity-40"
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
            onApply={() => {
              confirm.open({
                title: "Apply Rules",
                message: `Apply ${selectedRules.size} generated rule(s) to the firewall?`,
                confirmLabel: "Apply",
                onConfirm: () => handleApplyRules(result.rules, selectedRules),
              });
            }}
            canEdit={canEdit}
          />
        )}
      </Card>

      {/* -- Section 2: Existing PCAPs -- */}
      <Card title="Existing PCAP Files" padding="lg">
        <p className="mb-4 text-sm text-slate-400">
          Previously uploaded or captured PCAPs. Click Analyze to extract
          protocols and generate rules.
        </p>

        {pcaps.length === 0 ? (
          <div className="text-sm text-[var(--text-muted)]">No PCAP files found.</div>
        ) : (
          <div className="overflow-hidden rounded-xl border border-white/[0.08]">
            <table className="w-full text-sm">
              <thead className="bg-[var(--surface)] text-left text-xs uppercase tracking-wide text-[var(--text)]">
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
                  <tr key={p.name} className="border-t border-white/[0.06] table-row-hover transition-ui">
                    <td className="px-4 py-3 font-mono text-xs text-white">
                      {p.name}
                    </td>
                    <td className="px-4 py-3 text-[var(--text)]">
                      {p.interface || "-"}
                    </td>
                    <td className="px-4 py-3 text-[var(--text)]">
                      {fmtSize(p.sizeBytes)}
                    </td>
                    <td className="px-4 py-3 text-[var(--text)]">
                      {new Date(p.createdAt).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      {(p.tags ?? []).length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {p.tags!.map((t) => (
                            <span
                              key={t}
                              className="rounded-full bg-white/[0.08] px-2 py-0.5 text-xs text-slate-200"
                            >
                              {t}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-xs text-[var(--text-muted)]">-</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => handleAnalyzeExisting(p.name)}
                        disabled={existingAnalyzing === p.name}
                        className="rounded-md bg-blue-600 px-2 py-1 text-xs font-medium text-white hover:bg-blue-500 transition-ui disabled:opacity-40"
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
            <div className="mb-2 text-sm text-[var(--text)]">
              Results for{" "}
              <span className="font-mono text-blue-400">{existingResult.name}</span>
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
              onApply={() => {
                confirm.open({
                  title: "Apply Rules",
                  message: `Apply ${existingSelectedRules.size} generated rule(s) to the firewall?`,
                  confirmLabel: "Apply",
                  onConfirm: () =>
                    handleApplyRules(
                      existingResult.result.rules,
                      existingSelectedRules,
                    ),
                });
              }}
              canEdit={canEdit}
            />
          </div>
        )}
      </Card>
    </Shell>
  );
}

/* -- Analysis Results Component -- */

function AnalysisResults({
  result,
  selectedRules,
  onToggleRule,
  onToggleAll,
  onApply,
  canEdit,
}: {
  result: PolicyAnalysis;
  selectedRules: Set<string>;
  onToggleRule: (id: string) => void;
  onToggleAll: () => void;
  onApply: () => void;
  canEdit: boolean;
}) {
  const { stats, eventSummary, rules, profiles } = result;
  const protocolList = Object.keys(stats.protocols ?? {});
  const eventEntries = Object.entries(eventSummary ?? {}).sort(
    ([, a], [, b]) => b - a,
  );
  const flowCount = stats.flows?.length ?? 0;

  return (
    <div className="mt-4 space-y-4">
      {/* Stats summary */}
      <div className="grid gap-3 md:grid-cols-4">
        <StatCard label="Packets" value={stats.packetCount.toLocaleString()} />
        <StatCard label="Flows" value={flowCount.toLocaleString()} />
        <StatCard label="Duration" value={fmtDuration(stats.duration)} />
        <div className="rounded-xl border border-white/[0.08] bg-black/30 p-3">
          <div className="text-xs uppercase tracking-wide text-slate-400">
            Protocols
          </div>
          <div className="mt-1 flex flex-wrap gap-1">
            {protocolList.length > 0 ? (
              protocolList.map((p) => (
                <span
                  key={p}
                  className="rounded-full bg-white/[0.08] px-2 py-0.5 text-xs text-slate-200"
                >
                  {p} ({stats.protocols[p]})
                </span>
              ))
            ) : (
              <span className="text-xs text-[var(--text-muted)]">none detected</span>
            )}
          </div>
        </div>
      </div>

      {/* Event summary table */}
      {eventEntries.length > 0 && (
        <div className="overflow-hidden rounded-xl border border-white/[0.08]">
          <table className="w-full text-sm">
            <thead className="bg-[var(--surface)] text-left text-xs uppercase tracking-wide text-[var(--text)]">
              <tr>
                <th className="px-4 py-2">Protocol</th>
                <th className="px-4 py-2">Event Count</th>
              </tr>
            </thead>
            <tbody>
              {eventEntries.map(([proto, count]) => (
                <tr key={proto} className="border-t border-white/[0.06] table-row-hover transition-ui">
                  <td className="px-4 py-2 text-slate-200">{proto}</td>
                  <td className="px-4 py-2 font-mono text-xs text-slate-200">
                    {count.toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Learned profiles */}
      {profiles && profiles.length > 0 && (
        <>
          <h3 className="text-sm font-semibold text-[var(--text)]">
            Learned Profiles ({profiles.length})
          </h3>
          <div className="overflow-hidden rounded-xl border border-white/[0.08]">
            <table className="w-full text-sm">
              <thead className="bg-[var(--surface)] text-left text-xs uppercase tracking-wide text-[var(--text)]">
                <tr>
                  <th className="px-4 py-2">Protocol</th>
                  <th className="px-4 py-2">Source</th>
                  <th className="px-4 py-2">Destination</th>
                  <th className="px-4 py-2">Packets</th>
                  <th className="px-4 py-2">Read/Write</th>
                </tr>
              </thead>
              <tbody>
                {profiles.map((p, i) => (
                  <tr key={i} className="border-t border-white/[0.06] table-row-hover transition-ui">
                    <td className="px-4 py-2">
                      <span className="rounded-full bg-white/[0.08] px-2 py-0.5 text-xs text-slate-200">
                        {p.protocol}
                      </span>
                    </td>
                    <td className="px-4 py-2 font-mono text-xs text-[var(--text)]">
                      {p.sourceIP}
                    </td>
                    <td className="px-4 py-2 font-mono text-xs text-[var(--text)]">
                      {p.destIP}
                    </td>
                    <td className="px-4 py-2 font-mono text-xs text-[var(--text)]">
                      {p.packetCount}
                    </td>
                    <td className="px-4 py-2 text-xs">
                      {p.readSeen && (
                        <span className="mr-1 rounded-full bg-emerald-500/20 px-2 py-0.5 text-emerald-400">
                          Read
                        </span>
                      )}
                      {p.writeSeen && (
                        <span className="rounded-full bg-amber-500/20 px-2 py-0.5 text-amber-400">
                          Write
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* Generated rules */}
      {rules.length > 0 && (
        <>
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-[var(--text)]">
              Generated Rules ({rules.length})
            </h3>
            <div className="flex items-center gap-2">
              <button
                onClick={onToggleAll}
                className="rounded-md border border-white/[0.08] bg-white/[0.04] px-2 py-1 text-xs text-slate-200 transition-ui hover:bg-white/[0.08]"
              >
                {selectedRules.size === rules.length
                  ? "Deselect All"
                  : "Select All"}
              </button>
              {canEdit && (
                <button
                  onClick={onApply}
                  disabled={selectedRules.size === 0}
                  className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-500 transition-ui disabled:opacity-40"
                >
                  Apply {selectedRules.size} Rule(s)
                </button>
              )}
            </div>
          </div>
          <div className="overflow-hidden rounded-xl border border-white/[0.08]">
            <table className="w-full text-sm">
              <thead className="bg-[var(--surface)] text-left text-xs uppercase tracking-wide text-[var(--text)]">
                <tr>
                  <th className="w-8 px-4 py-2"></th>
                  <th className="px-4 py-2">Description</th>
                  <th className="px-4 py-2">Sources</th>
                  <th className="px-4 py-2">Destinations</th>
                  <th className="px-4 py-2">ICS Protocol</th>
                  <th className="px-4 py-2">Action</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((r) => (
                  <tr key={r.id} className="border-t border-white/[0.06] table-row-hover transition-ui">
                    <td className="px-4 py-2">
                      <input
                        type="checkbox"
                        checked={selectedRules.has(r.id)}
                        onChange={() => onToggleRule(r.id)}
                        className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]"
                      />
                    </td>
                    <td className="px-4 py-2 text-[var(--text)]">
                      {r.description || r.id}
                    </td>
                    <td className="px-4 py-2 font-mono text-xs text-[var(--text)]">
                      {(r.sources ?? []).join(", ") || "*"}
                    </td>
                    <td className="px-4 py-2 font-mono text-xs text-[var(--text)]">
                      {(r.destinations ?? []).join(", ") || "*"}
                    </td>
                    <td className="px-4 py-2">
                      {r.ics?.protocol ? (
                        <span className="rounded-full bg-white/[0.08] px-2 py-0.5 text-xs text-slate-200">
                          {r.ics.protocol}
                          {r.ics.functionCodes &&
                            r.ics.functionCodes.length > 0 &&
                            ` FC:${r.ics.functionCodes.join(",")}`}
                        </span>
                      ) : (
                        <span className="text-xs text-[var(--text-muted)]">-</span>
                      )}
                    </td>
                    <td className="px-4 py-2">
                      <span
                        className={`rounded-full px-2 py-0.5 text-xs ${
                          r.action === "ALLOW"
                            ? "bg-emerald-500/20 text-emerald-400"
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

      {rules.length === 0 && (
        <div className="text-sm text-[var(--text-muted)]">
          No rules generated from this PCAP. The capture may not contain
          recognizable ICS protocol traffic.
        </div>
      )}
    </div>
  );
}

/* -- Stat Card -- */

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-white/[0.08] bg-black/30 p-3">
      <div className="text-xs uppercase tracking-wide text-slate-400">
        {label}
      </div>
      <div className="mt-1 text-lg font-semibold text-[var(--text)]">{value}</div>
    </div>
  );
}
