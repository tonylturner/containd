"use client";

import type { RefObject, SetStateAction, Dispatch } from "react";

import { downloadPcapURL, type PcapItem } from "../../lib/api";
import { Card } from "../../components/Card";

type StringSetter = Dispatch<SetStateAction<string>>;
type PcapIfaceStats = [string, { count: number; sizeBytes: number }];
type PcapOption = { value: string; label: string };

type SavedPcapsCardProps = {
  canEdit: boolean;
  pcapQuery: string;
  setPcapQuery: StringSetter;
  onRefresh: () => void;
  refreshing: boolean;
  uploading: boolean;
  uploadInputRef: RefObject<HTMLInputElement>;
  onUpload: (file: File | null) => void;
  lastRefresh: Date | null;
  pcaps: PcapItem[];
  totalSizeMB: number;
  ifaceStats: PcapIfaceStats[];
  ifaceFilter: string;
  setIfaceFilter: StringSetter;
  visiblePcaps: PcapItem[];
  pcapTag: string;
  setPcapTag: StringSetter;
  onAddTag: (pcapName: string) => void;
  onReplayInline: (item: PcapItem) => void;
  onDelete: (item: PcapItem) => void;
};

export function SavedPcapsCard(props: SavedPcapsCardProps) {
  const {
    canEdit,
    pcapQuery,
    setPcapQuery,
    onRefresh,
    refreshing,
    uploading,
    uploadInputRef,
    onUpload,
    lastRefresh,
    pcaps,
    totalSizeMB,
    ifaceStats,
    ifaceFilter,
    setIfaceFilter,
    visiblePcaps,
    pcapTag,
    setPcapTag,
    onAddTag,
    onReplayInline,
    onDelete,
  } = props;

  return (
    <Card padding="lg">
      <h2 className="text-lg font-semibold text-[var(--text)]">Saved PCAPs</h2>
      <p className="mt-1 text-sm text-[var(--text)]">Download or replay captures from storage.</p>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <input
          value={pcapQuery}
          onChange={(e) => setPcapQuery(e.target.value)}
          placeholder="Search by name, iface, tag"
          className="w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none md:w-2/3"
        />
        <button
          onClick={onRefresh}
          className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-2 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
        >
          {refreshing ? "Refreshing..." : "Refresh"}
        </button>
        <button
          onClick={() => setPcapQuery("")}
          className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-2 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
        >
          Clear search
        </button>
        <button
          onClick={() => uploadInputRef.current?.click()}
          disabled={!canEdit || uploading}
          className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-2 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08] disabled:opacity-50"
        >
          {uploading ? "Uploading..." : "Upload PCAP"}
        </button>
        <input
          ref={uploadInputRef}
          type="file"
          accept=".pcap"
          className="hidden"
          onChange={(e) => void onUpload(e.target.files?.[0] ?? null)}
        />
      </div>
      {lastRefresh ? (
        <div className="mt-2 text-xs text-[var(--text-dim)]">
          Last refreshed: {lastRefresh.toLocaleTimeString()} · Auto-refresh every 8s
        </div>
      ) : null}
      <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-[var(--text-muted)]">
        <span className="rounded-full bg-amber-500/[0.1] px-2 py-0.5 text-[var(--text)]">{pcaps.length} total</span>
        <span className="rounded-full bg-amber-500/[0.1] px-2 py-0.5 text-[var(--text)]">
          {totalSizeMB.toFixed(1)} MB stored
        </span>
      </div>
      {ifaceStats.length > 0 ? (
        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-[var(--text)]">
          <button
            onClick={() => setIfaceFilter("all")}
            className={`rounded-full px-2 py-0.5 transition-ui ${
              ifaceFilter === "all" ? "bg-amber-500/[0.15] text-[var(--amber)]" : "bg-amber-500/[0.1] text-[var(--text)]"
            }`}
          >
            All interfaces
          </button>
          {ifaceStats.map(([iface, stats]) => (
            <button
              key={iface}
              onClick={() => setIfaceFilter(iface)}
              className={`rounded-full px-2 py-0.5 transition-ui ${
                ifaceFilter === iface ? "bg-amber-500/[0.15] text-[var(--amber)]" : "bg-amber-500/[0.1] text-[var(--text)]"
              }`}
            >
              {iface} · {stats.count}
            </button>
          ))}
        </div>
      ) : null}
      <div className="mt-4 overflow-hidden rounded-sm border border-amber-500/[0.15]">
        <table className="w-full text-left text-sm text-[var(--text)]">
          <thead className="bg-[var(--surface)] text-xs uppercase tracking-wide text-[var(--text-muted)]">
            <tr>
              <th className="px-3 py-2">Name</th>
              <th className="px-3 py-2">Iface</th>
              <th className="px-3 py-2">Size</th>
              <th className="px-3 py-2">Tags</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {visiblePcaps.length === 0 ? (
              <tr className="border-t border-amber-500/[0.1]">
                <td colSpan={6} className="px-3 py-3 text-sm text-[var(--text-muted)]">
                  No captures match your filters.
                </td>
              </tr>
            ) : (
              visiblePcaps.map((p) => (
                <tr key={p.name} className="border-t border-amber-500/[0.1] table-row-hover transition-ui">
                  <td className="px-3 py-2">
                    <div className="font-mono text-xs text-[var(--text)]">{p.name}</div>
                    <div className="text-[11px] text-[var(--text-muted)]">{new Date(p.createdAt).toLocaleString()}</div>
                  </td>
                  <td className="px-3 py-2">{p.interface || "—"}</td>
                  <td className="px-3 py-2">{(p.sizeBytes / (1024 * 1024)).toFixed(1)} MB</td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1">
                      {(p.tags ?? []).length ? (
                        (p.tags ?? []).map((t) => (
                          <span key={t} className="rounded-full bg-amber-500/[0.1] px-2 py-0.5 text-[10px] text-[var(--text)]">
                            {t}
                          </span>
                        ))
                      ) : (
                        <span className="text-xs text-[var(--text-dim)]">—</span>
                      )}
                    </div>
                    <div className="mt-1 flex items-center gap-1">
                      <input
                        value={pcapTag}
                        onChange={(e) => setPcapTag(e.target.value)}
                        placeholder="add tag"
                        className="w-24 rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-xs text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                      />
                      <button
                        onClick={() => onAddTag(p.name)}
                        disabled={!canEdit}
                        className="rounded-md border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs text-[var(--text)] transition-ui hover:bg-amber-500/[0.08] disabled:opacity-50"
                      >
                        Add
                      </button>
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    <span className="rounded-full bg-amber-500/[0.1] px-2 py-0.5 text-[10px] text-[var(--text)]">{p.status}</span>
                  </td>
                  <td className="px-3 py-2 text-right">
                    <a
                      href={downloadPcapURL(p.name)}
                      className="mr-2 inline-flex rounded-md border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
                    >
                      Download
                    </a>
                    <button
                      onClick={() => onReplayInline(p)}
                      disabled={!canEdit}
                      className="mr-2 rounded-md border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs text-[var(--text)] transition-ui hover:bg-amber-500/[0.08] disabled:opacity-50"
                    >
                      Replay
                    </button>
                    <button
                      onClick={() => onDelete(p)}
                      disabled={!canEdit}
                      className="rounded-md px-2 py-1 text-xs text-red-400 transition-ui hover:bg-red-500/10 disabled:opacity-50"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

type ReplayCardProps = {
  canEdit: boolean;
  replayName: string;
  setReplayName: StringSetter;
  replayIface: string;
  setReplayIface: StringSetter;
  replayRate: string;
  setReplayRate: StringSetter;
  pcaps: PcapItem[];
  ifaceOptions: PcapOption[];
  onReplaySubmit: () => void;
};

export function ReplayCard({
  canEdit,
  replayName,
  setReplayName,
  replayIface,
  setReplayIface,
  replayRate,
  setReplayRate,
  pcaps,
  ifaceOptions,
  onReplaySubmit,
}: ReplayCardProps) {
  return (
    <Card padding="lg">
      <h2 className="text-lg font-semibold text-[var(--text)]">Replay</h2>
      <p className="mt-1 text-sm text-[var(--text)]">Replay a saved PCAP back onto an interface.</p>
      <div className="mt-4 grid gap-3">
        <select
          disabled={!canEdit}
          value={replayName}
          onChange={(e) => setReplayName(e.target.value)}
          className="w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none disabled:opacity-50"
        >
          <option value="">Select a PCAP</option>
          {pcaps.map((p) => (
            <option key={p.name} value={p.name}>
              {p.name}
            </option>
          ))}
        </select>
        <select
          disabled={!canEdit}
          value={replayIface}
          onChange={(e) => setReplayIface(e.target.value)}
          className="w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none disabled:opacity-50"
        >
          <option value="">Replay interface</option>
          {ifaceOptions.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
        <input
          disabled={!canEdit}
          value={replayRate}
          onChange={(e) => setReplayRate(e.target.value)}
          placeholder="Replay rate (pps)"
          className="w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none disabled:opacity-50"
        />
        <button
          disabled={!canEdit || !replayName || !replayIface}
          onClick={onReplaySubmit}
          className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-2 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08] disabled:opacity-50"
        >
          Start replay
        </button>
      </div>
    </Card>
  );
}
