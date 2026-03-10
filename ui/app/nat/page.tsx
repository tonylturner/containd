"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import {
  api,
  isAdmin,
  type NATConfig,
  type PortForward,
  type Zone,
} from "../../lib/api";
import { Shell } from "../../components/Shell";
import { TipsBanner, type Tip } from "../../components/TipsBanner";
import { Card } from "../../components/Card";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";

/* ── helpers ───────────────────────────────────────────────────── */

function zoneLabel(zone: Zone): string {
  return zone.alias ? `${zone.alias} (${zone.name})` : zone.name;
}

function zoneName(zones: Zone[], name: string): string {
  const match = zones.find((z) => z.name === name);
  return match ? zoneLabel(match) : name;
}

/* ── page ──────────────────────────────────────────────────────── */

export default function NATPage() {
  const [zones, setZones] = useState<Zone[]>([]);
  const [nat, setNat] = useState<NATConfig>({ enabled: false });
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const tips: Tip[] = [
    {
      id: "nat:zones",
      title: "Create zones first",
      body: (
        <>
          Define zones in{" "}
          <Link href="/zones/" className="font-semibold text-[var(--amber)] hover:text-[var(--amber)]">
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
      body: "Add a port forward (DNAT) to make an internal server reachable from an external zone. Remember to also create a matching firewall allow rule.",
      when: () => zones.length > 0 && nat.enabled && (nat.portForwards ?? []).length === 0,
    },
  ];

  async function refresh() {
    const [z, n] = await Promise.all([api.listZones(), api.getNAT()]);
    setZones(z ?? []);
    setNat(n ?? { enabled: false });
  }

  useEffect(() => {
    refresh();
  }, []);

  return (
    <Shell
      title="NAT"
      actions={
        <button
          onClick={refresh}
          className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
        >
          Refresh
        </button>
      }
    >
      {!isAdmin() && (
        <div className="mb-4 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3 text-sm text-[var(--text)]">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      <TipsBanner tips={tips} className="mb-4" />
      {error && (
        <div className="mb-4 rounded-sm border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}
      {notice && (
        <div className="mb-4 rounded-sm border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400">
          {notice}
        </div>
      )}

      <NATCard
        zones={zones}
        nat={nat}
        onSave={async (cfg) => {
          setError(null);
          setNotice(null);
          const saved = await api.setNAT(cfg);
          if (!saved) {
            setError("Failed to update NAT (check zones).");
            return;
          }
          setNotice("NAT configuration saved.");
          refresh();
        }}
      />

      <PortForwardsCard
        zones={zones}
        nat={nat}
        onSave={async (cfg) => {
          setError(null);
          setNotice(null);
          const saved = await api.setNAT(cfg);
          if (!saved) {
            setError("Failed to update port forwards (check zones/ports).");
            return;
          }
          setNotice("Port forwarding configuration saved.");
          refresh();
        }}
      />
    </Shell>
  );
}

/* ── SNAT card ────────────────────────────────────────────────── */

function NATCard({
  zones,
  nat,
  onSave,
}: {
  zones: Zone[];
  nat: NATConfig;
  onSave: (cfg: NATConfig) => void;
}) {
  const [enabled, setEnabled] = useState(!!nat.enabled);
  const [egressZone, setEgressZone] = useState(nat.egressZone ?? "");
  const [sourceZones, setSourceZones] = useState<string[]>(
    nat.sourceZones ?? [],
  );

  useEffect(() => {
    setEnabled(!!nat.enabled);
    setEgressZone(nat.egressZone ?? "");
    setSourceZones(nat.sourceZones ?? []);
  }, [nat.enabled, nat.egressZone, nat.sourceZones]);

  const zoneOptions = (zones ?? [])
    .map((z) => ({ value: z.name, label: zoneLabel(z) }))
    .filter((z) => z.value);
  zoneOptions.sort((a, b) => a.label.localeCompare(b.label));

  const dirty =
    enabled !== !!nat.enabled ||
    egressZone !== (nat.egressZone ?? "") ||
    JSON.stringify((sourceZones ?? []).slice().sort()) !==
      JSON.stringify(((nat.sourceZones ?? []) as string[]).slice().sort());

  return (
    <div className="mb-6 overflow-hidden rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] shadow-card backdrop-blur">
      <div className="flex items-center justify-between border-b border-amber-500/[0.15] px-4 py-3">
        <div>
          <div className="text-sm font-semibold text-[var(--text)]">Source NAT (SNAT)</div>
          <div className="text-xs text-[var(--text-muted)]">
            Masquerade outbound traffic so internal hosts appear with the
            firewall&apos;s egress address. Changes apply on{" "}
            <span className="font-mono">commit</span>.
          </div>
        </div>
        <span
          className={
            enabled
              ? "rounded-full bg-emerald-500/20 px-2 py-0.5 text-xs text-emerald-400"
              : "rounded-full bg-amber-500/20 px-2 py-0.5 text-xs text-amber-400"
          }
        >
          {enabled ? "ENABLED" : "DISABLED"}
        </span>
      </div>

      <div className="grid gap-4 p-4 md:grid-cols-3">
        <Card padding="sm">
          <div className="text-xs font-semibold uppercase tracking-wide text-[var(--text)]">
            Enable
          </div>
          <div className="mt-2 flex items-center gap-3">
            <button
              disabled={!isAdmin()}
              onClick={() => setEnabled((v) => !v)}
              className={
                "rounded-sm border px-3 py-1.5 text-sm transition-ui " +
                (enabled
                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                  : "border-amber-500/[0.15] bg-[var(--surface2)] text-[var(--text)] hover:bg-amber-500/[0.08]") +
                (!isAdmin() ? " opacity-50" : "")
              }
            >
              {enabled ? "On" : "Off"}
            </button>
            <div className="text-xs text-[var(--text-muted)]">
              When enabled, defaults to <span className="font-mono">wan</span>{" "}
              egress and <span className="font-mono">lan, dmz</span> sources if
              empty.
            </div>
          </div>
        </Card>

        <Card padding="sm">
          <div className="text-xs font-semibold uppercase tracking-wide text-[var(--text)]">
            Egress Zone
          </div>
          <select
            disabled={!isAdmin()}
            value={egressZone}
            onChange={(e) => setEgressZone(e.target.value)}
            className="mt-2 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
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
          <div className="text-xs font-semibold uppercase tracking-wide text-[var(--text)]">
            Source Zones
          </div>
          <div className="mt-2 grid max-h-32 gap-1 overflow-auto pr-1 text-sm">
            {zoneOptions.length === 0 && (
              <div className="text-xs text-[var(--text-muted)]">No zones defined.</div>
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
                  <span className="text-[var(--text)]">{z.label}</span>
                </label>
              );
            })}
          </div>
          <div className="mt-2 text-xs text-[var(--text-muted)]">
            Leave empty to use default sources.
          </div>
        </Card>
      </div>

      {isAdmin() && (
        <div className="flex items-center justify-end gap-2 border-t border-amber-500/[0.15] px-4 py-3">
          <button
            disabled={!dirty}
            onClick={() =>
              onSave({
                enabled,
                egressZone: egressZone.trim() || undefined,
                sourceZones:
                  (sourceZones ?? []).map((z) => z.trim()).filter(Boolean) ||
                  undefined,
              })
            }
            className={
              "rounded-sm px-3 py-1.5 text-sm font-medium transition-ui " +
              (dirty
                ? "bg-[var(--amber)] text-white hover:brightness-110"
                : "bg-[var(--surface2)] text-[var(--text-dim)]")
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
  zones,
  nat,
  onSave,
}: {
  zones: Zone[];
  nat: NATConfig;
  onSave: (cfg: NATConfig) => void;
}) {
  const [items, setItems] = useState<PortForward[]>(nat.portForwards ?? []);
  const [newIngress, setNewIngress] = useState("wan");
  const [newProto, setNewProto] = useState<"tcp" | "udp">("tcp");
  const [newListen, setNewListen] = useState("");
  const [newDestIp, setNewDestIp] = useState("");
  const [newDestPort, setNewDestPort] = useState("");
  const [newSources, setNewSources] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [error, setError] = useState<string | null>(null);
  const confirm = useConfirm();

  useEffect(() => {
    setItems(nat.portForwards ?? []);
  }, [nat.portForwards]);

  const zoneOptions = (zones ?? [])
    .map((z) => ({ value: z.name, label: zoneLabel(z) }))
    .filter((z) => z.value);
  zoneOptions.sort((a, b) => a.label.localeCompare(b.label));

  const dirty = JSON.stringify(items) !== JSON.stringify(nat.portForwards ?? []);

  function validatePort(v: string): number | null {
    const n = Number(v);
    if (!Number.isFinite(n) || n <= 0 || n > 65535) return null;
    return Math.trunc(n);
  }

  async function add() {
    setError(null);
    const lp = validatePort(newListen);
    if (!lp) {
      setError("Listen port must be 1-65535.");
      return;
    }
    if (!newDestIp.trim()) {
      setError("Destination IP is required.");
      return;
    }
    const dp = newDestPort.trim() ? validatePort(newDestPort) ?? undefined : undefined;
    if (newDestPort.trim() && !dp) {
      setError("Destination port must be 1-65535.");
      return;
    }
    const id = typeof crypto !== "undefined" && "randomUUID" in crypto ? crypto.randomUUID() : `pf-${Date.now()}`;
    const pf: PortForward = {
      id,
      enabled: true,
      ingressZone: newIngress.trim(),
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
    setItems((prev) => [...prev, pf]);
    setNewListen("");
    setNewDestIp("");
    setNewDestPort("");
    setNewSources("");
    setNewDesc("");
  }

  async function save() {
    setError(null);
    onSave({ ...nat, portForwards: items });
  }

  function toggle(id: string, enabled: boolean) {
    setItems((prev) => prev.map((p) => (p.id === id ? { ...p, enabled } : p)));
  }

  function remove(id: string) {
    setItems((prev) => prev.filter((p) => p.id !== id));
  }

  function firewallLink(pf: PortForward): string {
    const params = new URLSearchParams();
    params.set("action", "create");
    params.set("dest", pf.destIp);
    params.set("port", String(pf.destPort ?? pf.listenPort));
    params.set("proto", pf.proto);
    if (pf.description) params.set("desc", `Allow DNAT: ${pf.description}`);
    return `/firewall/?${params.toString()}`;
  }

  return (
    <div className="mb-6 overflow-hidden rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] shadow-card backdrop-blur">
      <ConfirmDialog {...confirm.props} />
      <div className="flex items-center justify-between border-b border-amber-500/[0.15] px-4 py-3">
        <div>
          <div className="text-sm font-semibold text-[var(--text)]">Port Forwarding (DNAT)</div>
          <div className="text-xs text-[var(--text-muted)]">
            Destination NAT (prerouting) to expose internal services. You still need a matching{" "}
            <Link href="/firewall/" className="font-semibold text-[var(--amber)] hover:text-[var(--amber)]">
              firewall allow rule
            </Link>.
          </div>
        </div>
        {isAdmin() && (
          <button
            onClick={save}
            disabled={!dirty}
            className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50"
          >
            Save
          </button>
        )}
      </div>

      <div className="p-4">
        {!isAdmin() && (
          <div className="mb-3 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3 text-sm text-[var(--text)]">
            View-only mode: port forwarding changes are disabled.
          </div>
        )}
        {error && (
          <div className="mb-3 rounded-sm border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
            {error}
          </div>
        )}

        {isAdmin() && (
          <div className="grid gap-2 md:grid-cols-6">
            <select
              value={newIngress}
              onChange={(e) => setNewIngress(e.target.value)}
              className="input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
            >
              {zoneOptions.map((z) => (
                <option key={z.value} value={z.value}>
                  ingress:{z.label}
                </option>
              ))}
            </select>
            <select
              value={newProto}
              onChange={(e) => setNewProto(e.target.value as "tcp" | "udp")}
              className="input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
            >
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
            </select>
            <input
              value={newListen}
              onChange={(e) => setNewListen(e.target.value)}
              placeholder="listen port"
              className="input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
            />
            <input
              value={newDestIp}
              onChange={(e) => setNewDestIp(e.target.value)}
              placeholder="dest ip"
              className="input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
            />
            <input
              value={newDestPort}
              onChange={(e) => setNewDestPort(e.target.value)}
              placeholder="dest port (opt)"
              className="input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
            />
            <button
              onClick={add}
              className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-2 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
            >
              Add
            </button>

            <input
              value={newSources}
              onChange={(e) => setNewSources(e.target.value)}
              placeholder="sources CIDR (comma) (opt)"
              className="input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none md:col-span-3"
            />
            <input
              value={newDesc}
              onChange={(e) => setNewDesc(e.target.value)}
              placeholder="description (opt)"
              className="input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none md:col-span-3"
            />
          </div>
        )}

        <div className="mt-4 overflow-hidden rounded-sm border border-amber-500/[0.15]">
          <table className="w-full text-sm">
            <thead className="bg-[var(--surface)] text-left text-xs uppercase tracking-wide text-[var(--text)]">
              <tr>
                <th className="px-4 py-3">Ingress</th>
                <th className="px-4 py-3">Proto</th>
                <th className="px-4 py-3">Listen</th>
                <th className="px-4 py-3">Destination</th>
                <th className="px-4 py-3">Sources</th>
                <th className="px-4 py-3">Enabled</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.length === 0 && (
                <tr>
                  <td className="px-4 py-4 text-[var(--text-muted)]" colSpan={7}>
                    No port forwards configured. Port forwards (DNAT) expose internal services to external zones.
                  </td>
                </tr>
              )}
              {items.map((pf) => (
                <tr key={pf.id} className="border-t border-amber-500/[0.1] table-row-hover transition-ui">
                  <td className="px-4 py-3 text-[var(--text)]">{zoneName(zones, pf.ingressZone)}</td>
                  <td className="px-4 py-3 text-[var(--text)]">{pf.proto}</td>
                  <td className="px-4 py-3 font-mono text-xs text-[var(--text)]">
                    {pf.listenPort}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-[var(--text)]">
                    {pf.destIp}
                    {pf.destPort ? `:${pf.destPort}` : ""}
                  </td>
                  <td className="px-4 py-3 text-[var(--text)]">
                    {(pf.allowedSources ?? []).join(", ") || "any"}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={
                        pf.enabled
                          ? "rounded-full bg-emerald-500/20 px-2 py-0.5 text-xs text-emerald-400"
                          : "rounded-full bg-amber-500/20 px-2 py-0.5 text-xs text-amber-400"
                      }
                    >
                      {pf.enabled ? "on" : "off"}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right">
                    {isAdmin() && (
                      <div className="flex items-center justify-end gap-2">
                        <Link
                          href={firewallLink(pf)}
                          className="rounded-md border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs transition-ui hover:bg-amber-500/[0.08]"
                          title="Create matching firewall rule"
                        >
                          + FW Rule
                        </Link>
                        <button
                          onClick={() => toggle(pf.id, !pf.enabled)}
                          className="rounded-md border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs transition-ui hover:bg-amber-500/[0.08]"
                        >
                          {pf.enabled ? "Disable" : "Enable"}
                        </button>
                        <button
                          onClick={() =>
                            confirm.open({
                              title: "Delete port forward?",
                              message: `Remove the ${pf.proto}/${pf.listenPort} forward to ${pf.destIp}${pf.destPort ? `:${pf.destPort}` : ""}? This change is not saved until you click Save.`,
                              confirmLabel: "Delete",
                              variant: "danger",
                              onConfirm: () => remove(pf.id),
                            })
                          }
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
      </div>
    </div>
  );
}
