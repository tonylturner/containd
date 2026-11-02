"use client";

import { useAsyncRefresh } from "../../hooks/useAsyncRefresh";

import { useCallback, useMemo, useState, Fragment } from "react";

import { api, isAdmin, type ConntrackEntry } from "../../lib/api";
import type { ConntrackKillResult, ConntrackKillRequest, ConntrackKillTuple } from "../../lib/api-console";
import { Shell } from "../../components/Shell";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import { EmptyState } from "../../components/EmptyState";
import { ConnectionInspection } from "./connection-inspection";
import { formatEndpoint } from "../../lib/endpoint";

type Filter = {
  q: string;
};

function normalizeProto(p: string | undefined): string {
  return (p ?? "").toLowerCase().trim();
}

function isICMP(proto: string): proto is "icmp" | "icmpv6" {
  return proto === "icmp" || proto === "icmpv6";
}

/** A listed decimal field as a number; NaN when absent or malformed. */
function decimal(value: string | undefined): number {
  return value !== undefined && /^\d+$/.test(value) ? Number(value) : NaN;
}

/** The original tuple a kill selects, or null when the entry lacks one. */
function killTuple(e: ConntrackEntry): ConntrackKillTuple | null {
  const proto = normalizeProto(e.proto);
  const src = (e.src ?? "").trim();
  const dst = (e.dst ?? "").trim();
  if (!src || !dst) return null;
  if (isICMP(proto)) {
    const [icmpId, icmpType, icmpCode] = [e.icmpId, e.icmpType, e.icmpCode].map(decimal);
    if ([icmpId, icmpType, icmpCode].some(Number.isNaN)) return null;
    return { proto, src, dst, icmpId, icmpType, icmpCode };
  }
  if (proto !== "tcp" && proto !== "udp") return null;
  const sport = decimal(e.sport);
  const dport = decimal(e.dport);
  if (!sport || !dport) return null;
  return { proto, src, dst, sport, dport };
}

/**
 * One tuple direction for display: endpoints with their ports, or bare
 * addresses followed by the ICMP identifier when the entry carries one. An
 * engine that does not report ICMP identifiers yields bare addresses.
 */
function tupleText(proto: string, src: string | undefined, sport: string | undefined, dst: string | undefined, dport: string | undefined, icmpId: string | undefined): string {
  const endpoints = `${formatEndpoint(src, sport)} → ${formatEndpoint(dst, dport)}`;
  return isICMP(normalizeProto(proto)) && icmpId !== undefined ? `${endpoints} (id ${icmpId})` : endpoints;
}

/** The original tuple, prefixed with its protocol, as the kill dialog names it. */
function describeTuple(e: ConntrackEntry): string {
  return `${e.proto} ${tupleText(e.proto, e.src, e.sport, e.dst, e.dport, e.icmpId)}`;
}

/** The reply tuple (NAT) column: ports, or the ICMP identifier NAT may rewrite. */
function replyTuple(e: ConntrackEntry): string {
  if (!e.replySrc) return "—";
  return tupleText(e.proto, e.replySrc, e.replySport, e.replyDst, e.replyDport, e.replyIcmpId);
}

export default function SessionsPage() {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const canKill = isAdmin();
  const confirm = useConfirm();
  const [entries, setEntries] = useState<ConntrackEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [available, setAvailable] = useState(false);
  const [filter, setFilter] = useState<Filter>({ q: "" });
  const [limit, setLimit] = useState(500);
  const [scope, setScope] = useState<ConntrackKillRequest["scope"]>("connection");
  const [durationSecs, setDurationSecs] = useState(60);
  const [killResult, setKillResult] = useState<ConntrackKillResult | null>(null);
  const [killing, setKilling] = useState(false);

  const { loading, refresh } = useAsyncRefresh(useCallback(async () => {
    const data = await api.listConntrack(limit);
    setError(null);
    if (!data.ok) {
      setError(`Connections unavailable: ${data.error}`);
      setEntries([]);
      setAvailable(false);
      return;
    }
    setEntries(data.data);
    setAvailable(true);
  }, [limit]));

  const filtered = useMemo(() => {
    const q = filter.q.trim().toLowerCase();
    if (!q) return entries;
    return entries.filter((e) => {
      const hay = [
        e.proto,
        e.state ?? "",
        e.src ?? "",
        e.sport ?? "",
        e.dst ?? "",
        e.dport ?? "",
        e.icmpId ?? "",
        e.mark ?? "",
        ...(e.tags ?? []),
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [entries, filter.q]);

  async function kill(e: ConntrackEntry) {
    if (!canKill) return;
    setError(null);
    const tuple = killTuple(e);
    if (!tuple) {
      setError("Cannot kill: missing tuple fields.");
      return;
    }
    setKilling(true);
    setKillResult(null);
    const res = await api.killConntrack({ ...tuple, scope, durationSecs });
    setKilling(false);
    if (!res.ok) {
      setError(`Kill failed: ${res.error}`);
      return;
    }
    setKillResult(res.data);
    await refresh();
  }

  function handleKill(e: ConntrackEntry) {
    const proto = normalizeProto(e.proto);
    const icmp = isICMP(proto);
    const reach = scope === "client-service"
      ? `This ends all of this client's connections to that service and prevents new ones during the interval.${icmp ? " For ICMP the service is the query type, so all of the client's pings to that host stop." : ""}`
      : icmp ? "Only this exact ping is blocked. A new ICMP identifier is allowed." : "Only this exact connection is blocked. A fresh source port is allowed.";
    const closure = proto === "tcp" ? "TCP closure is signalled on each endpoint's next packet, not confirmed." : "Matching packets are dropped.";
    confirm.open({
      title: scope === "connection" ? "Kill connection" : "Kill client-service connections",
      message: `Revoke ${describeTuple(e)} for ${durationSecs} seconds? ${reach} ${closure}`,
      confirmLabel: "Kill",
      variant: "danger",
      onConfirm: () => kill(e),
    });
  }

  return (
    <Shell
      title="Sessions"
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={filter.q}
            onChange={(e) => setFilter({ q: e.target.value })}
            placeholder="Filter (ip, port, proto, state, tag)…"
            className="input-industrial w-64 max-w-full"
          />
          <select
            value={String(limit)}
            onChange={(e) => setLimit(Number(e.target.value) || 200)}
            className="rounded-xs border bg-(--surface) px-2 py-1.5 text-sm text-(--text) transition-ui outline-hidden"
          >
            <option value="200">200</option>
            <option value="500">500</option>
            <option value="2000">2000</option>
          </select>
          <button
            onClick={refresh}
            className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text)"
          >
            Refresh
          </button>
        </div>
      }
    >
      {!canKill && (
        <div className="mb-4 rounded-xs border bg-(--surface2) px-4 py-3 text-sm text-(--text)">
          View-only mode: session kill requires admin.
        </div>
      )}
      {canKill && (
        <div className="mb-4 flex flex-wrap items-end gap-4 rounded-xs border bg-(--surface2) px-4 py-3 text-sm">
          <label className="flex flex-col gap-1">Kill scope
            <select aria-label="Kill scope" value={scope} onChange={(e) => setScope(e.target.value as ConntrackKillRequest["scope"])} className="input-industrial">
              <option value="connection">Exact connection</option>
              <option value="client-service">Client-service (all connections)</option>
            </select>
          </label>
          <label className="flex flex-col gap-1">Revocation seconds (1–3600)
            <input aria-label="Revocation seconds" type="number" min={1} max={3600} value={durationSecs} onChange={(e) => setDurationSecs(Number(e.target.value))} className="input-industrial w-40" />
          </label>
          <p className="text-(--text-muted)">{scope === "connection" ? "A fresh source port, or a new ICMP identifier, is a new connection and is allowed." : "Ends all this client's connections to the service, including reconnects. For ICMP, all its pings to that host."}</p>
        </div>
      )}
      {killResult && (
        <div role="status" aria-label="Connection revocation result" className="mb-4 rounded-xs border bg-(--surface2) px-4 py-3 text-sm">
          <p>Connection entries removed: {killResult.conntrackDeleted ? "yes" : "no"} ({killResult.deleted}/{killResult.matched}){killResult.deleteError ? ` — ${killResult.deleteError}` : ""}</p>
          <p>Revocation installed: {killResult.revocationInstalled ? `yes, until ${killResult.blockedUntil}` : `no — ${killResult.revocationError}`}</p>
          <p>{killResult.closure}</p>
        </div>
      )}
      {!loading && error && (
        <div role="alert" aria-label="Connections error" className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}

      {!loading && !available ? null : !loading && filtered.length === 0 ? (
        <EmptyState
          title="No connections to display"
          description={entries.length === 0 ? "Verified empty: the kernel returned no connections." : "No sessions match the current filter."}
        />
      ) : (
        <div className="rounded-xs border bg-(--surface) overflow-hidden shadow-card">
          <div className="flex items-center justify-between px-4 py-3">
            <div>
              <div className="text-sm text-(--text)">
                {loading ? "Loading…" : `${filtered.length} shown / ${entries.length} total`}
              </div>
              <div className="text-xs text-(--text-muted)">
                Live IPv4 and IPv6 connections. Tags are the labels of the running connection-label rules that match each connection as opened. ICMP rows show the identifier and query type in place of ports. Kill supports TCP, UDP, ICMP and ICMPv6; TCP resets are sent in response to matching packets, and other matching packets are dropped.
              </div>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-(--surface)">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-(--text-dim)">Proto</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-(--text-dim)">State</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-(--text-dim)">Src</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-(--text-dim)">Sport</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-(--text-dim)">Dst</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-(--text-dim)">Dport</th>
                  <th className="px-4 py-3 text-right text-xs font-medium uppercase tracking-wider text-(--text-dim)">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((e, idx) => {
                  const key = JSON.stringify([e.proto, e.src, e.sport, e.icmpId, e.dst, e.dport, e.icmpType, e.icmpCode, idx]);
                  const detailId = `session-detail-${encodeURIComponent(key)}`;
                  return (
                  <Fragment key={key}>
                  <tr className="table-row-hover transition-ui border-t">
                    <td className="px-4 py-3 font-medium text-(--text)">{e.proto || "—"}</td>
                    <td className="px-4 py-3 text-(--text)">{e.state || "—"}</td>
                    <td className="px-4 py-3 text-(--text)">{e.src || "—"}</td>
                    <td className="px-4 py-3 text-(--text)">{e.icmpId !== undefined ? `id ${e.icmpId}` : e.sport || "—"}</td>
                    <td className="px-4 py-3 text-(--text)">{e.dst || "—"}</td>
                    <td className="px-4 py-3 text-(--text)">{e.icmpType !== undefined ? `type ${e.icmpType} code ${e.icmpCode ?? "—"}` : e.dport || "—"}</td>
                    <td className="px-4 py-3 text-right">
                      <button type="button" aria-expanded={!!expanded[key]} aria-controls={detailId}
                        onClick={() => setExpanded(old => ({ ...old, [key]: !old[key] }))}
                        className="rounded-xs border px-2 py-1 text-xs">Inspect connection</button>
                      {(e.tags?.length || e.mark || e.replySrc) && <span className="mt-1 block text-xs text-(--text-muted)">{e.tags?.length ? `Tags: ${e.tags.length} · ` : ""}{e.mark ? `Mark: ${e.mark} · ` : ""}{e.replySrc ? "Reply tuple (NAT) available" : ""}</span>}
                      <button
                        disabled={!canKill || killing || killTuple(e) === null || !Number.isInteger(durationSecs) || durationSecs < 1 || durationSecs > 3600}
                        onClick={() => handleKill(e)}
                        className={
                          canKill
                            ? "rounded-xs px-3 py-1 text-xs text-red-400 transition-ui hover:bg-red-500/10"
                            : "rounded-xs border bg-(--surface2) px-3 py-1 text-xs text-(--text-dim)"
                        }
                        title={canKill ? "Revoke connection for the selected interval" : "Admin only"}
                      >
                        Kill
                      </button>
                    </td>
                  </tr>
                  <ConnectionInspection entry={e} id={detailId} open={!!expanded[key]} reply={replyTuple(e)} />
                  </Fragment>
                );})}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <ConfirmDialog {...confirm.props} />
    </Shell>
  );
}
