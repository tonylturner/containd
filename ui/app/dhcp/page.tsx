"use client";

import { useAsyncRefresh } from "../../hooks/useAsyncRefresh";

import { revisionError, ConfigEditNotice, useConfigLoad, useConfigEditor } from "../../lib/use-config-editor";

import { useConfigRefresh } from "../../lib/use-config-refresh";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";

import { api, isAdmin, type DHCPConfig, type DHCPLease, type DHCPPool, type DHCPReservation, type DHCPStatus } from "../../lib/api";
import { Shell } from "../../components/Shell";
import { useToast } from "../../components/ToastProvider";
import { SaveStateLine } from "../../components/SaveStateLine";
import { useSaveAction } from "../../hooks/useSaveAction";
import { Skeleton } from "../../components/Skeleton";
import { Sparkline } from "../../components/Sparkline";
import { InfoTip } from "../../components/InfoTip";
import { ServiceStatusStrip } from "../system/services/service-presentation";
import { Card } from "../../components/Card";

function normalize(cfg: DHCPConfig | null): DHCPConfig {
  return {
    ...cfg,
    enabled: cfg?.enabled ?? false,
    listenIfaces: cfg?.listenIfaces ?? ["lan2"],
    leaseSeconds: cfg?.leaseSeconds ?? 3600,
    router: cfg?.router ?? "",
    dnsServers: cfg?.dnsServers ?? [],
    domain: cfg?.domain ?? "",
    authoritative: cfg?.authoritative ?? false,
    pools: cfg?.pools ?? [],
    reservations: cfg?.reservations ?? [],
  };
}

function poolsToText(pools: DHCPPool[]): string {
  return pools.map((p) => `${p.iface},${p.start},${p.end}`).join("\n");
}

function textToPools(text: string): DHCPPool[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const [iface, start, end] = l.split(",").map((s) => s.trim());
      return { iface: iface || "", start: start || "", end: end || "" };
    });
}

function reservationsToText(reservations: DHCPReservation[]): string {
  return reservations.map((r) => `${r.iface},${r.mac},${r.ip}`).join("\n");
}

function textToReservations(text: string): DHCPReservation[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const [iface, mac, ip] = l.split(",").map((s) => s.trim());
      return { iface: iface || "", mac: mac || "", ip: ip || "" };
    });
}

export default function DHCPPage() {
  const canEdit = isAdmin();
  const { canSave, loadError, checkLoaded } = useConfigLoad();
  const toast = useToast();
  const { conflictProps, editor, cfg, setCfg, dirty, readConfig: adoptConfig, write, text, setText } = useConfigEditor(() => normalize(null), false);
  const [status, setStatus] = useState<DHCPStatus | null>(null);
  const save = useSaveAction();
  const [error, setError] = useState<string | null>(null);
  const [leases, setLeases] = useState<DHCPLease[]>([]);
  const [leaseError, setLeaseError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const { loading, refresh } = useAsyncRefresh(useCallback(async ({ keepEdits = true }: { keepEdits?: boolean } = {}) => {
    try {
      const svc = await api.getServicesStatus();
      setError(null);
      setStatus(svc?.dhcp ?? null);
      const currentSnapshot = await api.getDHCP();
      const current = (currentSnapshot?.data ?? null);
      if (!checkLoaded(current)) return;
      const next = normalize(current);
      adoptConfig({ data: next, revision: currentSnapshot?.revision ?? "" }, keepEdits);
      toast("DHCP status refreshed", "success");
      setLastUpdated(new Date());
    } catch (e) {
      checkLoaded(null);
      setError(e instanceof Error ? e.message : "Failed to refresh DHCP status.");
      toast("Failed to refresh DHCP status", "error");
    }
  }, [checkLoaded, toast, adoptConfig]));

  const { loading: leasesLoading, refresh: refreshLeases } = useAsyncRefresh(useCallback(async ({ silent = false }: { silent?: boolean } = {}) => {
    try {
      const r = await api.listDHCPLeases();
      setLeaseError(null);
      setLeases(r?.leases ?? []);
      if (!silent) toast("Leases updated", "success");
    } catch (e) {
      setLeaseError(e instanceof Error ? e.message : "Failed to load DHCP leases.");
      setLeases([]);
      if (!silent) toast("Failed to load leases", "error");
    }
  }, [toast]));

  useConfigRefresh(refresh);

  useEffect(() => {
    const t = window.setInterval(() => {
      refreshLeases({ silent: true });
    }, 10_000);
    return () => window.clearInterval(t);
  }, [refreshLeases]);

  useEffect(() => {
    if (!autoRefresh) return;
    const t = window.setInterval(() => {
      void refresh();
    }, 15_000);
    return () => window.clearInterval(t);
  }, [autoRefresh, refresh]);

  const listenIfacesText = text("listenIfaces", (cfg.listenIfaces ?? []).join(", "));
  const dnsServersText = text("dnsServers", (cfg.dnsServers ?? []).join(", "));
  const poolsText = text("pools", poolsToText(cfg.pools ?? []));
  const reservationsText = text("reservations", reservationsToText(cfg.reservations ?? []));

  async function onSave() {
    if (!canEdit || !canSave || loading) return;
    setError(null);
    const payload = { ...cfg,
      listenIfaces: listenIfacesText.split(",").map((s) => s.trim()).filter(Boolean),
      dnsServers: dnsServersText.split(",").map((s) => s.trim()).filter(Boolean),
      pools: textToPools(poolsText), reservations: textToReservations(reservationsText),
    };
    const saved = await save.run("save", () => write(base => api.setDHCP(base, payload), { replace: data => normalize(data) }), {
      success: "DHCP staged — commit to apply.",
      failure: "Failed to save DHCP settings.",
    });
    if (!saved) return;
    if (!saved.ok) {
      setError(revisionError(saved));
      return;
    }
  }

  return (
    <Shell
      title="DHCP"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={() => void refresh({ keepEdits: false })}
            className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
          >
            Refresh
          </button>
          {canEdit && (
            <button
              onClick={onSave}
              disabled={!canSave || loading || save.pending !== null}
              className="rounded-xs bg-(--amber) px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-60"
            >
              {save.pending ? "Saving…" : "Save"}
            </button>
          )}
          <label className="ml-2 flex items-center gap-2 text-xs text-(--text)">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="h-4 w-4 rounded-sm bg-(--surface)"
            />
            Auto
          </label>
        </div>
      }
    >
      <ConfigEditNotice {...conflictProps} onReload={() => refresh({ keepEdits: false })} superseded={false} />
      {loadError && <p role="alert" className="mb-4 text-sm text-red-400">{loadError}</p>}
      <ServiceStatusStrip configured={canSave ? cfg.enabled : undefined} attention={!status ? "Live service status unavailable — use Refresh to retry" : status.last_error || status.fault?.message || (status.state === "faulted" ? "Service faulted" : undefined)} updated={status?.last_render} />
      {!canEdit && (
        <div className="mb-4 rounded-xs border bg-(--surface) px-4 py-3 text-sm text-(--text)">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      {!loading && error && (
        <div className="mb-4 rounded-xs border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}
      <p className="mb-4 text-xs text-(--text-muted)">
        Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : "\u2014"} {autoRefresh ? "(auto)" : ""}
      </p>
      <div className="mb-4 flex items-center justify-between rounded-xs border bg-(--surface) px-3 py-2 text-xs text-(--text)">
        <span>Related LAN services</span>
        <Link href="/system/services/dns/" className="text-(--amber) hover:text-(--amber)">
          DNS resolver &rarr;
        </Link>
      </div>

      <Card>
        <h2 className="text-lg font-semibold text-(--text)">DHCPv4 Server</h2>
        <p className="mt-1 text-sm text-(--text)">
          Assign IPv4 addresses to LAN clients after saving and applying these settings.
        </p>

        <div className="mt-4 grid gap-3 md:grid-cols-2">
          <label className="flex items-center gap-2 text-sm text-(--text)">
            <input
              type="checkbox"
              checked={cfg.enabled ?? false}
              disabled={!canEdit || !canSave}
              onChange={(e) => setCfg((c) => ({ ...c, enabled: e.target.checked }))}
              className="h-4 w-4"
            />
            Enable DHCP server
            <InfoTip label="Provides IPv4 leases on LAN interfaces when enabled." />
          </label>

          <label className="flex items-center gap-2 text-sm text-(--text)">
            <input
              type="checkbox"
              checked={cfg.authoritative ?? false}
              disabled={!canEdit || !canSave}
              onChange={(e) => setCfg((c) => ({ ...c, authoritative: e.target.checked }))}
              className="h-4 w-4"
            />
            Authoritative
            <InfoTip label="Sends DHCPNAK for addresses this server cannot lease on served interfaces. Eligible addresses are adopted in either mode. Leave off when another DHCP server owns the subnet." />
          </label>

          <div>
            <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text-muted)">
              Listen Interfaces (CSV)
              <InfoTip label="Comma-separated interfaces where DHCP listens (e.g., lan2, lan3)." />
            </label>
            <input
              value={listenIfacesText}
              disabled={!canEdit || !canSave}
              onChange={(e) => setText("listenIfaces", e.target.value)}
              placeholder="lan2, lan3"
              className="mt-1 w-full input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
            />
          </div>
          <div>
            <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text-muted)">
              Router (Gateway)
              <InfoTip label="Default gateway handed to clients (usually the firewall LAN IP)." />
            </label>
            <input
              value={cfg.router ?? ""}
              disabled={!canEdit || !canSave}
              onChange={(e) => setCfg((c) => ({ ...c, router: e.target.value }))}
              placeholder="192.168.1.1"
              className="mt-1 w-full input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
            />
          </div>
          <div className="md:col-span-2">
            <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text-muted)">
              Pools (one per line)
              <InfoTip label="Format: iface,start,end (validated on save)." />
            </label>
            <textarea
              rows={6}
              value={poolsText}
              disabled={!canEdit || !canSave}
              onChange={(e) => setText("pools", e.target.value)}
              placeholder={"lan2,192.168.10.100,192.168.10.200\nlan3,192.168.20.100,192.168.20.200"}
              className="mt-1 w-full rounded-xs border bg-(--surface) px-3 py-2 font-mono text-xs text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
            />
          </div>
          <details className="md:col-span-2 rounded-xs border bg-(--surface) px-4 py-3" open={(cfg.leaseSeconds ?? 3600) !== 3600 || !!cfg.domain || !!cfg.dnsServers?.length || !!cfg.reservations?.length}>
            <summary className="cursor-pointer text-sm text-(--text)"><span>Advanced options</span>{((cfg.leaseSeconds ?? 3600) !== 3600 || !!cfg.domain || !!cfg.dnsServers?.length || !!cfg.reservations?.length) && <span className="ml-2 text-xs text-(--text-muted)">Configured settings</span>}</summary>
            <div className="mt-3 grid gap-3 md:grid-cols-2">

              <div>
                <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text-muted)">
                  Lease Seconds
                  <InfoTip label="How long clients keep their IPs before renewal (default 3600)." />
                </label>
                <input
                  type="number"
                  value={cfg.leaseSeconds ?? 3600}
                  disabled={!canEdit || !canSave}
                  onChange={(e) => setCfg((c) => ({ ...c, leaseSeconds: Number(e.target.value) || 0 }))}
                  className="mt-1 w-full input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
                />
              </div>

              <div>
                <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text-muted)">
                  DNS Servers (CSV)
                  <InfoTip label="DNS servers handed to clients (leave empty to use the firewall DNS)." />
                </label>
                <input
                  value={dnsServersText}
                  disabled={!canEdit || !canSave}
                  onChange={(e) => setText("dnsServers", e.target.value)}
                  placeholder="192.168.1.1, 1.1.1.1"
                  className="mt-1 w-full input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
                />
              </div>

              <div className="md:col-span-2">
                <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text-muted)">
                  Domain (optional)
                  <InfoTip label="Optional search domain handed to clients." />
                </label>
                <input
                  value={cfg.domain ?? ""}
                  disabled={!canEdit || !canSave}
                  onChange={(e) => setCfg((c) => ({ ...c, domain: e.target.value }))}
                  placeholder="lab.local"
                  className="mt-1 w-full input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
                />
              </div>

              <div className="md:col-span-2">
                <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text-muted)">
                  Reservations (one per line)
                  <InfoTip label="Format: iface,mac,ip (must fall inside pool for that iface)." />
                </label>
                <textarea
                  rows={6}
                  value={reservationsText}
                  disabled={!canEdit || !canSave}
                  onChange={(e) => setText("reservations", e.target.value)}
                  placeholder={"lan2,aa:bb:cc:dd:ee:ff,192.168.10.50"}
                  className="mt-1 w-full rounded-xs border bg-(--surface) px-3 py-2 font-mono text-xs text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
                />
              </div>
            </div>
          </details>
        </div>

        <SaveStateLine state={save.state} saved="staged — commit to apply." />
        {dirty && (
          <p
            role="status"
            aria-label="Unsaved edits"
            className={editor.superseded
              ? "mt-3 rounded-xs border border-amber/30 bg-amber/10 px-3 py-2 text-xs text-amber"
              : "mt-3 text-xs text-(--text-muted)"}
          >
            {editor.superseded
              ? "Unsaved edits kept: the DHCP settings changed on the server while you were editing. Save replaces them with your edits; Refresh discards your edits."
              : "Unsaved edits — Save stages them; Refresh discards them."}
          </p>
        )}
      </Card>

      <Card className="mb-4">
        <h2 className="text-base font-semibold text-(--text)">Activity</h2>
        <h3 className="text-sm font-semibold text-(--text)">Live runtime status</h3>
        {loading ? (
          <div className="mt-3 space-y-2">
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-8 w-1/2" />
          </div>
        ) : !status ? (
          <div role="status" className="mt-3 text-sm text-(--text-muted)">
            Unknown — live service status unavailable.
            <button type="button" onClick={() => refresh()} className="ml-2 underline">Retry</button>
          </div>
        ) : (
          <div className="mt-3 grid gap-2 text-sm text-(--text) md:grid-cols-2">
            <div>
              Enabled: <span className="text-(--text)">{typeof status?.enabled === "boolean" ? (status.enabled ? "yes" : "no") : "Unknown"}</span>
            </div>
            <div>
              Pools: <span className="text-(--text)">{status?.pools ?? "Unknown"}</span>
            </div>
            <div>
              Reservations: <span className="text-(--text)">{status?.reservations ?? "Unknown"}</span>
            </div>
            <div>
              Listen ifaces: <span className="text-(--text)">{status?.listen_ifaces ?? "Unknown"}</span>
            </div>
            <div>
              Rate: <span className="text-(--text)">{typeof status?.rate_per_min === "number" ? status.rate_per_min.toFixed(1) : "Unknown"} / min</span>
            </div>
            <div>
              Errors: <span>{typeof status?.errors_rate_per_min === "number" ? status.errors_rate_per_min.toFixed(1) : "Unknown"} / min</span>
            </div>
            {status?.last_error ? (
              <div className="md:col-span-2 rounded-xs border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
                {status.last_error}
              </div>
            ) : null}
            {status?.note ? (
              <div className="md:col-span-2 text-xs text-(--text-muted)">{status.note}</div>
            ) : null}
            {status?.sparkline.length ? (
              <div className="md:col-span-2">
                <Sparkline
                  values={status.sparkline}
                  color="var(--teal)"
                  background="linear-gradient(180deg, rgba(6,182,212,0.08), rgba(59,130,246,0.04))"
                  title="DHCP events per minute"
                />
              </div>
            ) : null}
          </div>
        )}
      </Card>
      <Card className="mt-6">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-(--text)">Active Leases</h2>
            <p className="mt-1 text-sm text-(--text)">Leases issued by the DHCP service on this appliance (best-effort).</p>
          </div>
          <div className="flex items-center gap-2">
            <a
              href="/events?filter=service&kind=service.dhcp.reservation"
              className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
            >
              Reservation events
            </a>
            <button
              onClick={() => refreshLeases()}
              className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
            >
              Refresh
            </button>
          </div>
        </div>

        {!leasesLoading && leaseError && (
          <div className="mt-4 rounded-xs border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
            {leaseError}
          </div>
        )}

        <div className="mt-4 overflow-x-auto rounded-xs border">
          {leasesLoading ? (
            <div className="space-y-2 p-3">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : (
            <table className="w-full text-left text-sm text-(--text)">
              <thead className="bg-(--surface) text-xs uppercase tracking-wide text-(--text-muted)">
                <tr>
                  <th className="px-3 py-2">Iface</th>
                  <th className="px-3 py-2">IP</th>
                  <th className="px-3 py-2">MAC</th>
                  <th className="px-3 py-2">Hostname</th>
                  <th className="px-3 py-2">Expires</th>
                </tr>
              </thead>
              <tbody>
                {leases.length === 0 ? (
                  <tr className="border-t">
                    <td colSpan={5} className="px-3 py-3 text-sm text-(--text-muted)">
                      No leases.
                    </td>
                  </tr>
                ) : (
                  leases.map((l) => (
                    <tr key={`${l.iface}-${l.mac}-${l.ip}`} className="border-t table-row-hover transition-ui">
                      <td className="px-3 py-2 font-mono text-xs">{l.iface}</td>
                      <td className="px-3 py-2 font-mono text-xs">{l.ip}</td>
                      <td className="px-3 py-2 font-mono text-xs">{l.mac}</td>
                      <td className="px-3 py-2">{l.hostname || "\u2014"}</td>
                      <td className="px-3 py-2 font-mono text-xs">{l.expiresAt}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          )}
        </div>
      </Card>
    </Shell>
  );
}
