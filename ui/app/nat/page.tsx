"use client";

import type { ConfigBase } from "../../lib/config-boundary";

import { useConfigView, matchingRevisions } from "../../lib/use-config-revision";

import { useAsyncRefresh } from "../../hooks/useAsyncRefresh";

import { revisionError, useConfigEditor, ConfigEditNotice } from "../../lib/use-config-editor";
import { useConfigForm } from "../../lib/use-config-form";

import { useConfigRefresh } from "../../lib/use-config-refresh";

import { useCallback, useEffect, useLayoutEffect, useRef, useState, type SetStateAction } from "react";
import Link from "next/link";

import {
  api,
  isAdmin,
  type ApiResult,
  type ForwardPublishResult,
  type NATConfig,
  type PortForward,
  type Zone,
  type FirewallRule,
} from "../../lib/api";
import { NetworkSetup } from "../interfaces/network-setup";
import { Shell } from "../../components/Shell";
import { TipsBanner, type Tip } from "../../components/TipsBanner";
import { Card } from "../../components/Card";
import { SkeletonList } from "../../components/Skeleton";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import { formatEndpoint } from "../../lib/endpoint";
import { validateIPv4, validatePort } from "../../lib/validate";
import { zoneLabel, zoneName } from "../../lib/zones";
import { forwardPlacementMessage } from "../../lib/forward-placement";

const UNAVAILABLE = "NAT settings unavailable — the server did not return the NAT configuration and zones.";

/* ── page ──────────────────────────────────────────────────────── */

export default function NATPage() {
  const natView = useConfigView({ nat: { enabled: false } as NATConfig, zones: [] as Zone[], rules: null as FirewallRule[] | null });
  const { readConfig } = natView;
  const { nat, zones, rules } = natView.data;
  const natRevision = natView.state.baseRevision ?? "";
  // Until the first answer the settings are unknown, not disabled or empty.
  const [loaded, setLoaded] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [noticeWarning, setNoticeWarning] = useState(false);
  const writable = useRef(false);
  useLayoutEffect(() => { writable.current = loaded && !loadError && isAdmin(); }, [loaded, loadError]);

  const tips: Tip[] = [
    {
      id: "nat:zones",
      title: "Create zones first",
      body: (
        <>
          Define zones in{" "}
          <Link href="/zones/" className="font-semibold text-(--amber) hover:text-(--amber)">
            Zones
          </Link>{" "}
          so you can assign egress and source zones.
        </>
      ),
      when: () => zones.length === 0,
    },
    {
      id: "nat:enable",
      title: "Enable SNAT for outbound access",
      body: "Turn on source NAT (masquerade) so internal hosts can reach the Internet via the WAN zone.",
      when: () => zones.length > 0 && !nat.enabled,
    },
    {
      id: "nat:portfwd",
      title: "Expose internal services",
      body: "A port forward translates destinations only. Firewall policy decides delivery; publishing can create a matching allow rule where safe.",
      when: () => zones.length > 0 && nat.enabled && (nat.portForwards ?? []).length === 0,
    },
  ];

  const { initialLoading: loading, refresh } = useAsyncRefresh(useCallback(async ({ keepEdits = true }: { keepEdits?: boolean } = {}) => {
    const [zSnapshot, nSnapshot, rSnapshot] = await Promise.all([api.listZones(), api.getNAT(), api.listFirewallRules()]);
    if (zSnapshot && nSnapshot && (!matchingRevisions(zSnapshot, nSnapshot) || (rSnapshot && !matchingRevisions(nSnapshot, rSnapshot)))) { setLoadError("Configuration changed during loading. Refresh to review one consistent snapshot."); return; }
    const z = (zSnapshot?.data ?? null);
    const n = (nSnapshot?.data ?? null);
    const r = (rSnapshot?.data ?? null);
    // Never save stand-in settings. After the first success, keep drafts
    // mounted but disabled while the current server copy is unavailable.
    if (z && n) {
      setLoadError(null);
      readConfig({ data: { nat: n, zones: z, rules: r }, revision: nSnapshot!.revision }, keepEdits);
      setLoaded(true);
      if (!keepEdits) setReloadKey((n) => n + 1);
    } else {
      setLoadError(UNAVAILABLE);
    }
  }, [readConfig]));

  useConfigRefresh(refresh);

  return (
    <Shell
      title="NAT"
      actions={
        <button
          onClick={() => refresh({ keepEdits: false })}
          className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
        >
          Refresh
        </button>
      }
    >
      <NetworkSetup current="/nat/" />
      {!isAdmin() && (
        <div className="mb-4 rounded-xs border bg-(--surface) px-4 py-3 text-sm text-(--text)">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      {!loading && !loadError && <TipsBanner tips={tips} className="mb-4" />}
      {error && (
        <div className="mb-4 rounded-xs border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}
      {notice && (
        <div role="status" className={`mb-4 rounded-xs border px-4 py-3 text-sm ${noticeWarning ? "border-amber/30 bg-amber/10 text-amber" : "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"}`}>
          {notice}
        </div>
      )}

      {loadError ? (
        <div role="alert" className="mb-4 rounded-xs border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {loadError}
        </div>
      ) : null}
      {loading ? <SkeletonList rows={4} /> : loaded ? <fieldset disabled={!!loadError} className="min-w-0">
      <NATCard
        key={`snat-${reloadKey}`}
        zones={zones}
        nat={nat}
        revision={natRevision}
        onSave={(base, cfg) => natView.writer(async (revision, cfg: NATConfig) => {
          if (!writable.current) return { ok: false, error: UNAVAILABLE };
          setError(null);
          setNotice(null);
          setNoticeWarning(false);
          const saved = await api.setNAT(revision, cfg);
          if (!saved.ok) {
            setError(revisionError(saved));
            return saved;
          }
          setNotice(
            saved.warning
              ? `NAT configuration staged — commit to apply. Warning: ${saved.warning}`
              : "NAT configuration staged — commit to apply.",
          );
          refresh();
          return saved;
        }, (view, saved) => ({ ...view, nat: saved }))(base, cfg)}
      />

      <PortForwardsCard
        key={`dnat-${reloadKey}`}
        zones={zones}
        nat={nat}
        revision={natRevision}
        rules={rules}
        onPublish={(base, forward, allowRule) => natView.writer(async (revision, forward: PortForward, allowRule: boolean) => {
          if (!writable.current) return { ok: false, error: UNAVAILABLE };
          setError(null);
          setNotice(null);
          const result = await api.publishPortForward(revision, forward, allowRule);
          if (!result.ok) {
            setError(revisionError(result));
            return result;
          }
          setNotice(forwardPlacementMessage(result.data) + (result.warning ? ` Warning: ${result.warning}` : ""));
          setNoticeWarning(!!result.data.placement?.warning);
          await refresh();
          return result;
        }, (view, saved) => {
          let rules = [...(view.rules ?? [])];
          if (saved.placement?.reason === "generated") {
            const placement = saved.placement;
            rules = rules.filter(row => row.id !== placement.rule.id);
            rules.splice(placement.index, 0, placement.rule);
          }
          return { ...view, nat: { ...view.nat, portForwards: [
            ...(view.nat.portForwards ?? []).filter(row => row.id !== saved.forward.id), saved.forward,
          ] }, rules };
        })(base, forward, allowRule)}
        onDelete={(base, id) => natView.writer(async (revision, id: string) => {
          if (!writable.current) return { ok: false, error: UNAVAILABLE };
          setError(null);
          setNotice(null);
          setNoticeWarning(false);
          const result = await api.deletePortForward(revision, id);
          if (!result.ok) {
            setError(revisionError(result));
            return result;
          }
          setNotice(`Port forward deleted — commit to apply. Deleted rules: ${result.data.deletedRuleIds.join(", ") || "none"}. Edited rules: ${result.data.editedRuleIds.join(", ") || "none"}.${result.warning ? ` Warning: ${result.warning}` : ""}`);
          await refresh();
          return result;
        }, (view, saved, id) => ({ ...view,
          nat: { ...view.nat, portForwards: (view.nat.portForwards ?? []).filter(row => row.id !== id) },
          rules: view.rules?.filter(row => !saved.deletedRuleIds.includes(row.id)).map(row => saved.editedRuleIds.includes(row.id)
            ? { ...row, viaForwards: row.viaForwards?.filter(forward => forward !== id) } : row) ?? null,
        }))(base, id)}
        onSave={(base, cfg) => natView.writer(async (revision, cfg: NATConfig) => {
          if (!writable.current) return { ok: false, error: UNAVAILABLE };
          setError(null);
          setNotice(null);
          setNoticeWarning(false);
          const saved = await api.setNAT(revision, cfg);
          if (!saved.ok) {
            setError(revisionError(saved));
            return saved;
          }
          setNotice(
            saved.warning
              ? `Port forwarding configuration staged — commit to apply. Warning: ${saved.warning}`
              : "Port forwarding configuration staged — commit to apply.",
          );
          refresh();
          return saved;
        }, (view, saved) => ({ ...view, nat: saved }))(base, cfg)}
      />
      </fieldset> : null}
    </Shell>
  );
}

function snat(nat: NATConfig): NATConfig {
  return { enabled: !!nat.enabled, egressZone: nat.egressZone ?? "", sourceZones: nat.sourceZones ?? [] };
}

/* ── SNAT card ────────────────────────────────────────────────── */

function NATCard({
  revision,
  zones,
  nat,
  onSave,
}: {
  zones: Zone[];
  nat: NATConfig;
  revision: string;
  onSave: (revision: ConfigBase, cfg: NATConfig) => Promise<ApiResult<NATConfig> | null>;
}) {
  const { conflictProps, editor, cfg, setCfg, readConfig: adoptConfig, write, dirty } = useConfigEditor(() => snat(nat), true, revision);
  const enabled = !!cfg.enabled;
  const egressZone = cfg.egressZone ?? "";
  const sourceZones = cfg.sourceZones ?? [];
  const setEnabled = (value: SetStateAction<boolean>) => setCfg((c) => ({ ...c, enabled: typeof value === "function" ? value(!!c.enabled) : value }));
  const setEgressZone = (egressZone: string) => setCfg((c) => ({ ...c, egressZone }));
  const setSourceZones = (value: SetStateAction<string[]>) => setCfg((c) => ({ ...c, sourceZones: typeof value === "function" ? value(c.sourceZones ?? []) : value }));
  useEffect(() => { adoptConfig({ data: snat(nat), revision: revision ?? "" }, true); }, [nat, adoptConfig, revision]);

  const zoneOptions = (zones ?? [])
    .map((z) => ({ value: z.name, label: zoneLabel(z) }))
    .filter((z) => z.value);
  zoneOptions.sort((a, b) => a.label.localeCompare(b.label));

  return (
    <div className="mb-6 overflow-x-auto rounded-xs border bg-(--surface) shadow-card backdrop-blur-sm">
      <ConfigEditNotice {...conflictProps} onReload={() => window.location.reload()} superseded={editor.superseded} />
      <div className="flex items-center justify-between border-b px-4 py-3">
        <div>
          <div className="text-sm font-semibold text-(--text)">Source NAT (SNAT)</div>
          <div className="text-xs text-(--text-muted)">
            Masquerade outbound traffic so internal hosts appear with the
            firewall&apos;s egress address. Changes apply on{" "}
            <span className="font-mono">commit</span>.
          </div>
        </div>
        <span
          className={
            enabled
              ? "rounded-full bg-emerald-500/20 px-2 py-0.5 text-xs text-emerald-400"
              : "rounded-full px-2 py-0.5 text-xs "
          }
        >
          {enabled ? "ENABLED" : "DISABLED"}
        </span>
      </div>

      <div className="grid gap-4 p-4 md:grid-cols-3">
        <Card padding="sm">
          <div className="text-xs font-semibold uppercase tracking-wide text-(--text)">
            Enable
          </div>
          <div className="mt-2 flex items-center gap-3">
            <button
              disabled={!isAdmin()}
              onClick={() => setEnabled((v) => !v)}
              className={
                "rounded-xs border px-3 py-1.5 text-sm transition-ui " +
                (enabled
                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                  : "bg-(--surface2) text-(--text) ") +
                (!isAdmin() ? " opacity-50" : "")
              }
            >
              {enabled ? "On" : "Off"}
            </button>
            <div className="text-xs text-(--text-muted)">
              When enabled, defaults to <span className="font-mono">wan</span>{" "}
              egress and <span className="font-mono">lan, dmz</span> sources if
              empty.
            </div>
          </div>
        </Card>

        <Card padding="sm">
          <div className="text-xs font-semibold uppercase tracking-wide text-(--text)">
            Egress Zone
          </div>
          <select
            disabled={!isAdmin()}
            value={egressZone}
            onChange={(e) => setEgressZone(e.target.value)}
            className="mt-2 w-full input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
          >
            <option value="">(default: wan)</option>
            {zoneOptions.map((z) => (
              <option key={z.value} value={z.value}>
                {z.label}
              </option>
            ))}
          </select>
        </Card>

        <Card padding="sm">
          <div className="text-xs font-semibold uppercase tracking-wide text-(--text)">
            Source Zones
          </div>
          <div className="mt-2 grid max-h-32 gap-1 overflow-auto pr-1 text-sm">
            {zoneOptions.length === 0 && (
              <div className="text-xs text-(--text-muted)">No zones defined.</div>
            )}
            {zoneOptions.map((z) => {
              const checked = sourceZones.includes(z.value);
              return (
                <label key={z.value} className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    disabled={!isAdmin()}
                    checked={checked}
                    onChange={(e) => {
                      const next = e.target.checked;
                      setSourceZones((prev) => {
                        const p = prev ?? [];
                        if (next) return Array.from(new Set([...p, z.value]));
                        return p.filter((x) => x !== z.value);
                      });
                    }}
                  />
                  <span className="text-(--text)">{z.label}</span>
                </label>
              );
            })}
          </div>
          <div className="mt-2 text-xs text-(--text-muted)">
            Leave empty to use default sources.
          </div>
        </Card>
      </div>

      {isAdmin() && (
        <div className="flex items-center justify-end gap-2 border-t px-4 py-3">
          <button
            disabled={!dirty}
            onClick={async () => {
              await write(base => onSave(base, { ...nat, ...cfg,
                egressZone: egressZone.trim() || undefined,
                sourceZones: sourceZones.map((z) => z.trim()).filter(Boolean),
              }), { replace: data => snat(data) });
            }}
            className={
              "rounded-xs px-3 py-1.5 text-sm font-medium transition-ui " +
              (dirty
                ? "bg-(--amber) text-white hover:brightness-110"
                : "bg-(--surface2) text-(--text-dim)")
            }
          >
            Save NAT
          </button>
        </div>
      )}
    </div>
  );
}

/* ── Port forwards (DNAT) card ────────────────────────────────── */

function PortForwardsCard({
  revision,
  zones,
  nat,
  onSave,
  rules,
  onPublish,
  onDelete,
}: {
  zones: Zone[];
  nat: NATConfig;
  revision: string;
  onSave: (revision: ConfigBase, cfg: NATConfig) => Promise<ApiResult<NATConfig> | null>;
  rules: FirewallRule[] | null;
  onPublish: (revision: ConfigBase, forward: PortForward, allowRule: boolean) => Promise<ApiResult<ForwardPublishResult> | null>;
  onDelete: (revision: ConfigBase, id: string) => Promise<Awaited<ReturnType<typeof api.deletePortForward>> | null>;
}) {
  const { conflictProps, editor, cfg: items, setCfg: setItems, readConfig: adoptConfig, write, dirty } = useConfigEditor<PortForward[]>(nat.portForwards ?? [], true, revision);
  const form = useConfigForm({
    ingressChoice: "", newProto: "tcp" as "tcp" | "udp",
    newListen: "", newDestIp: "", newDestPort: "", newSources: "", newDesc: "",
    allowRule: true,
  }, nat, revision);
  const { readConfig: refreshForm } = form;
  useEffect(() => { refreshForm({ data: nat, revision: revision ?? "" }, true); }, [nat, refreshForm, revision]);
  const [ingressChoice, setIngressChoice] = form.field("ingressChoice");
  const [newProto, setNewProto] = form.field("newProto");
  const [newListen, setNewListen] = form.field("newListen");
  const [newDestIp, setNewDestIp] = form.field("newDestIp");
  const [newDestPort, setNewDestPort] = form.field("newDestPort");
  const [newSources, setNewSources] = form.field("newSources");
  const [newDesc, setNewDesc] = form.field("newDesc");
  const [allowRule, setAllowRule] = form.field("allowRule");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const confirm = useConfirm();

  useEffect(() => {
    adoptConfig({ data: nat.portForwards ?? [], revision: revision ?? "" }, true);
  }, [nat.portForwards, adoptConfig, revision]);

  const zoneOptions = (zones ?? [])
    .map((z) => ({ value: z.name, label: zoneLabel(z) }))
    .filter((z) => z.value);
  zoneOptions.sort((a, b) => a.label.localeCompare(b.label));

  // Keep an explicit choice even if a refresh removes its zone. Never
  // silently stage a different ingress on the user's behalf.
  const hasZone = (name: string) => zoneOptions.some((z) => z.value === name);
  const newIngress = ingressChoice || (hasZone("wan") ? "wan" : "");

  // One banner serves the whole row, so each message names its field.
  async function addPortForward() {
    setError(null);
    if (!newIngress) {
      setError("Ingress zone is required.");
      return;
    }
    if (!hasZone(newIngress)) {
      setError("Ingress zone is no longer available. Choose a configured zone.");
      return;
    }
    if (!newListen.trim()) {
      setError("Listen port is required.");
      return;
    }
    const listenError = validatePort(newListen);
    if (listenError) {
      setError(`Listen port: ${listenError}.`);
      return;
    }
    if (!newDestIp.trim()) {
      setError("Destination IP is required.");
      return;
    }
    const destIpError = validateIPv4(newDestIp);
    if (destIpError) {
      setError(`Destination IP: ${destIpError}.`);
      return;
    }
    const destPortError = validatePort(newDestPort);
    if (destPortError) {
      setError(`Destination port: ${destPortError}.`);
      return;
    }
    const lp = Number(newListen.trim());
    const dp = newDestPort.trim() ? Number(newDestPort.trim()) : undefined;
    // getRandomValues also works on HTTP appliances, where randomUUID requires
    // a secure context. Never fall back to collision-prone millisecond IDs.
    const id = `pf-${Array.from(crypto.getRandomValues(new Uint32Array(4)),
      (part) => part.toString(16).padStart(8, "0")).join("")}`;
    const pf: PortForward = {
      id,
      enabled: true,
      ingressZone: newIngress,
      proto: newProto,
      listenPort: lp,
      destIp: newDestIp.trim(),
      destPort: dp,
      allowedSources: newSources
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      description: newDesc.trim() || undefined,
    };
    setBusy(true);
    await form.write(base => onPublish(base, pf, allowRule), ["newListen", "newDestIp", "newDestPort", "newSources", "newDesc"]);
    setBusy(false);
  }

  async function save() {
    setError(null);
    setBusy(true);
    await write(base => onSave(base, { ...nat, portForwards: items }), { replace: data => data.portForwards ?? [] });
    setBusy(false);
  }

  function toggle(id: string, enabled: boolean) {
    setItems((prev) => prev.map((p) => (p.id === id ? { ...p, enabled } : p)));
  }

  function confirmDelete(pf: PortForward) {
    if (!rules) return;
    const affected = rules.filter((r) => r.viaForwards?.includes(pf.id));
    const deleted = affected.filter((r) => r.viaForwards?.length === 1);
    const edited = affected.filter((r) => (r.viaForwards?.length ?? 0) > 1);
    confirm.open({
      title: "Delete port forward?",
      message: <div className="space-y-2">
        <p>Remove {pf.proto}/{pf.listenPort} → {formatEndpoint(pf.destIp, pf.destPort || pf.listenPort)}?</p>
        <p>Rules to delete: {deleted.map((r) => r.id).join(", ") || "none"}.</p>
        <p>Rules to edit (remove this forward): {edited.map((r) => r.id).join(", ") || "none"}.</p>
        <p>Changes are staged; commit to apply.</p>
      </div>,
      confirmLabel: "Delete",
      variant: "danger",
      onConfirm: async () => {
        setBusy(true);
        await write(base => onDelete(base, pf.id), { patch: rows => rows.filter(item => item.id !== pf.id), prefixes: [`${JSON.stringify(pf.id)}.`] });
        setBusy(false);
      },
    });
  }

  return (
    <div className="mb-6 overflow-x-auto rounded-xs border bg-(--surface) shadow-card backdrop-blur-sm">
      <ConfigEditNotice {...conflictProps} onReload={() => window.location.reload()} superseded={editor.superseded || form.editor.superseded} />
      <ConfigEditNotice superseded={false} {...form.conflictProps} onReload={() => window.location.reload()} />
      <ConfirmDialog {...confirm.props} />
      <div className="flex items-center justify-between border-b px-4 py-3">
        <div>
          <div className="text-sm font-semibold text-(--text)">Port Forwarding (DNAT)</div>
          <div className="text-xs text-(--text-muted)">
            Port forwards only translate destinations. Delivery is decided by{" "}
            <Link href="/firewall/" className="font-semibold text-(--amber) hover:text-(--amber)">
              ordered firewall policy
            </Link>.
          </div>
        </div>
        {isAdmin() && (
          <button
            onClick={save}
            disabled={!dirty || busy}
            className="rounded-xs bg-(--amber) px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50"
          >
            Save
          </button>
        )}
      </div>

      <div className="p-4">
        {!isAdmin() && (
          <div className="mb-3 rounded-xs border bg-(--surface) px-4 py-3 text-sm text-(--text)">
            View-only mode: port forwarding changes are disabled.
          </div>
        )}
        {error && (
          <div className="mb-3 rounded-xs border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
            {error}
          </div>
        )}
        {dirty && <p className="mb-3 text-xs text-(--text-muted)">Save enabled/disabled changes before adding or deleting a forward.</p>}
        {rules === null && <p className="mb-3 text-xs text-(--text-muted)">Firewall rules unavailable; refresh before deleting a forward or viewing its rule links.</p>}

        <fieldset disabled={busy} className="min-w-0">
        {isAdmin() && (
          <div className="grid gap-2 md:grid-cols-6">
            <select
              aria-label="Ingress zone"
              value={newIngress}
              onChange={(e) => setIngressChoice(e.target.value)}
              className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
            >
              {!newIngress && (
                <option value="" disabled>
                  ingress: choose a zone
                </option>
              )}
              {ingressChoice && !hasZone(ingressChoice) && (
                <option value={ingressChoice}>ingress:{ingressChoice} (no longer on server)</option>
              )}
              {zoneOptions.map((z) => (
                <option key={z.value} value={z.value}>
                  ingress:{z.label}
                </option>
              ))}
            </select>
            <select
              value={newProto}
              onChange={(e) => setNewProto(e.target.value as "tcp" | "udp")}
              className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
            >
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
            </select>
            <input
              value={newListen}
              onChange={(e) => setNewListen(e.target.value)}
              placeholder="listen port"
              className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
            />
            <input
              value={newDestIp}
              onChange={(e) => setNewDestIp(e.target.value)}
              placeholder="dest ip"
              className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
            />
            <input
              value={newDestPort}
              onChange={(e) => setNewDestPort(e.target.value)}
              placeholder="dest port (opt)"
              className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
            />
            <button
              onClick={addPortForward}
              disabled={dirty}
              className="rounded-xs border bg-(--surface2) px-3 py-2 text-sm text-(--text) transition-ui"
            >
              Add
            </button>

            <input
              value={newSources}
              onChange={(e) => setNewSources(e.target.value)}
              placeholder="sources CIDR (comma) (opt)"
              className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden md:col-span-3"
            />
            <input
              value={newDesc}
              onChange={(e) => setNewDesc(e.target.value)}
              placeholder="description (opt)"
              className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden md:col-span-3"
            />
            <label className="flex items-center gap-2 text-sm text-(--text) md:col-span-6">
              <input type="checkbox" checked={allowRule} onChange={(e) => setAllowRule(e.target.checked)} />
              Create matching allow rule
            </label>
          </div>
        )}

        <div className="mt-4 overflow-x-auto rounded-xs border">
          <table className="w-full text-sm">
            <thead className="bg-(--surface) text-left text-xs uppercase tracking-wide text-(--text)">
              <tr>
                <th className="px-4 py-3">Ingress</th>
                <th className="px-4 py-3">Proto</th>
                <th className="px-4 py-3">Listen</th>
                <th className="px-4 py-3">Destination</th>
                <th className="px-4 py-3">Sources</th>
                <th className="px-4 py-3">Enabled</th>
                <th className="px-4 py-3">Rules</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.length === 0 && (
                <tr>
                  <td className="px-4 py-4 text-(--text-muted)" colSpan={8}>
                    No port forwards configured. Port forwards (DNAT) expose internal services to external zones.
                  </td>
                </tr>
              )}
              {items.map((pf) => (
                <tr key={pf.id} className="border-t table-row-hover transition-ui">
                  <td className="px-4 py-3 text-(--text)">{zoneName(zones, pf.ingressZone)}</td>
                  <td className="px-4 py-3 text-(--text)">{pf.proto}</td>
                  <td className="px-4 py-3 font-mono text-xs text-(--text)">
                    {pf.listenPort}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-(--text)">
                    {formatEndpoint(pf.destIp, pf.destPort || pf.listenPort)}
                  </td>
                  <td className="px-4 py-3 text-(--text)">
                    {(pf.allowedSources ?? []).join(", ") || "any"}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={
                        pf.enabled
                          ? "rounded-full bg-emerald-500/20 px-2 py-0.5 text-xs text-emerald-400"
                          : "rounded-full px-2 py-0.5 text-xs "
                      }
                    >
                      {pf.enabled ? "on" : "off"}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs">
                    {rules === null ? "unavailable" : rules.filter((r) => r.viaForwards?.includes(pf.id)).map((r) => (
                      <Link key={r.id} href={`/firewall/#${encodeURIComponent(`rule-${r.id}`)}`} className="mr-2 text-(--amber) underline">{r.id}</Link>
                    ))}
                    {rules && !rules.some((r) => r.viaForwards?.includes(pf.id)) && "none"}
                  </td>
                  <td className="px-4 py-3 text-right">
                    {isAdmin() && (
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => toggle(pf.id, !pf.enabled)}
                          className="rounded-md border bg-(--surface2) px-2 py-1 text-xs transition-ui"
                        >
                          {pf.enabled ? "Disable" : "Enable"}
                        </button>
                        <button
                          disabled={dirty || rules === null}
                          onClick={() => confirmDelete(pf)}
                          className="rounded-md px-2 py-1 text-xs text-red-400 transition-ui hover:bg-red-500/10"
                        >
                          Delete
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        </fieldset>
      </div>
    </div>
  );
}
