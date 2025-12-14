"use client";

import { useEffect, useState } from "react";

import { api, isAdmin, type PolicyRule, type RoutingConfig, type StaticRoute } from "../../lib/api";
import { Shell } from "../../components/Shell";

function normCIDR(s: string) {
  return s.trim();
}

export default function RoutingPage() {
  const [cfg, setCfg] = useState<RoutingConfig>({ routes: [], rules: [] });
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const [routeDst, setRouteDst] = useState("");
  const [routeGw, setRouteGw] = useState("");
  const [routeIface, setRouteIface] = useState("");
  const [routeTable, setRouteTable] = useState("0");
  const [routeMetric, setRouteMetric] = useState("");

  const [ruleSrc, setRuleSrc] = useState("");
  const [ruleDst, setRuleDst] = useState("");
  const [ruleTable, setRuleTable] = useState("");
  const [rulePrio, setRulePrio] = useState("");

  async function refresh() {
    const r = await api.getRouting();
    setCfg({
      routes: r?.routes ?? [],
      rules: r?.rules ?? [],
    });
  }

  useEffect(() => {
    refresh();
  }, []);

  async function save(next: RoutingConfig) {
    setError(null);
    setSaving(true);
    const updated = await api.setRouting(next);
    setSaving(false);
    if (!updated) {
      setError("Failed to save routing config.");
      return;
    }
    setCfg({
      routes: updated.routes ?? [],
      rules: updated.rules ?? [],
    });
  }

  async function addRoute() {
    if (!isAdmin()) return;
    setError(null);
    const dst = normCIDR(routeDst);
    if (!dst) {
      setError("Route destination is required (CIDR or 'default').");
      return;
    }
    const tableNum = Number(routeTable || "0");
    const metricNum = routeMetric.trim() ? Number(routeMetric.trim()) : undefined;
    const nextRoute: StaticRoute = {
      dst,
      gateway: routeGw.trim() || undefined,
      iface: routeIface.trim() || undefined,
      table: Number.isFinite(tableNum) ? tableNum : 0,
      metric: metricNum && Number.isFinite(metricNum) ? metricNum : undefined,
    };
    const next: RoutingConfig = {
      routes: [...(cfg.routes ?? []), nextRoute],
      rules: cfg.rules ?? [],
    };
    await save(next);
    setRouteDst("");
    setRouteGw("");
    setRouteIface("");
    setRouteTable("0");
    setRouteMetric("");
  }

  async function deleteRoute(idx: number) {
    if (!isAdmin()) return;
    const next: RoutingConfig = {
      routes: (cfg.routes ?? []).filter((_, i) => i !== idx),
      rules: cfg.rules ?? [],
    };
    await save(next);
  }

  async function addRule() {
    if (!isAdmin()) return;
    setError(null);
    const tableNum = Number(ruleTable.trim());
    if (!Number.isFinite(tableNum) || tableNum <= 0) {
      setError("Policy rule table is required and must be > 0.");
      return;
    }
    const prioNum = rulePrio.trim() ? Number(rulePrio.trim()) : undefined;
    const nextRule: PolicyRule = {
      table: tableNum,
      priority: prioNum && Number.isFinite(prioNum) ? prioNum : undefined,
      src: ruleSrc.trim() ? normCIDR(ruleSrc) : undefined,
      dst: ruleDst.trim() ? normCIDR(ruleDst) : undefined,
    };
    const next: RoutingConfig = {
      routes: cfg.routes ?? [],
      rules: [...(cfg.rules ?? []), nextRule],
    };
    await save(next);
    setRuleSrc("");
    setRuleDst("");
    setRuleTable("");
    setRulePrio("");
  }

  async function deleteRule(idx: number) {
    if (!isAdmin()) return;
    const next: RoutingConfig = {
      routes: cfg.routes ?? [],
      rules: (cfg.rules ?? []).filter((_, i) => i !== idx),
    };
    await save(next);
  }

  return (
    <Shell
      title="Routing"
      actions={
        <button
          onClick={refresh}
          className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
        >
          Refresh
        </button>
      }
    >
      {!isAdmin() && (
        <div className="mb-4 rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-200">
          View-only mode: configuration changes are disabled.
        </div>
      )}

      {error && (
        <div className="mb-4 rounded-xl border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-amber">
          {error}
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">Static routes</h2>
            {saving && <span className="text-xs text-slate-400">saving…</span>}
          </div>

          {isAdmin() && (
            <div className="mt-3 grid gap-2 md:grid-cols-2">
              <input
                value={routeDst}
                onChange={(e) => setRouteDst(e.target.value)}
                placeholder="dst (CIDR or default)"
                className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
              />
              <input
                value={routeGw}
                onChange={(e) => setRouteGw(e.target.value)}
                placeholder="gateway (optional)"
                className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
              />
              <input
                value={routeIface}
                onChange={(e) => setRouteIface(e.target.value)}
                placeholder="iface (logical or OS dev, optional)"
                className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
              />
              <div className="grid grid-cols-2 gap-2">
                <input
                  value={routeTable}
                  onChange={(e) => setRouteTable(e.target.value)}
                  placeholder="table (0=main)"
                  className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
                />
                <input
                  value={routeMetric}
                  onChange={(e) => setRouteMetric(e.target.value)}
                  placeholder="metric (optional)"
                  className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
                />
              </div>
              <div className="md:col-span-2 flex justify-end">
                <button
                  onClick={addRoute}
                  className="rounded-lg bg-mint/20 px-4 py-2 text-sm font-semibold text-mint hover:bg-mint/30"
                >
                  Add route
                </button>
              </div>
            </div>
          )}

          <div className="mt-4 overflow-hidden rounded-xl border border-white/10">
            <table className="w-full text-sm">
              <thead className="bg-black/30 text-left text-xs uppercase tracking-wide text-slate-300">
                <tr>
                  <th className="px-4 py-3">Dst</th>
                  <th className="px-4 py-3">Gateway</th>
                  <th className="px-4 py-3">Iface</th>
                  <th className="px-4 py-3">Table</th>
                  <th className="px-4 py-3">Metric</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {(cfg.routes ?? []).length === 0 && (
                  <tr>
                    <td className="px-4 py-4 text-slate-400" colSpan={6}>
                      No static routes configured.
                    </td>
                  </tr>
                )}
                {(cfg.routes ?? []).map((r, idx) => (
                  <tr key={`${r.dst}-${idx}`} className="border-t border-white/5">
                    <td className="px-4 py-3 font-medium text-white">{r.dst}</td>
                    <td className="px-4 py-3 text-slate-200">{r.gateway ?? "—"}</td>
                    <td className="px-4 py-3 text-slate-200">{r.iface ?? "—"}</td>
                    <td className="px-4 py-3 text-slate-200">{r.table ?? 0}</td>
                    <td className="px-4 py-3 text-slate-200">{r.metric ?? "—"}</td>
                    <td className="px-4 py-3 text-right">
                      {isAdmin() ? (
                        <button
                          onClick={() => deleteRoute(idx)}
                          className="rounded-md bg-white/5 px-3 py-1.5 text-xs text-slate-200 hover:bg-white/10"
                        >
                          Delete
                        </button>
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">Policy-based routing (ip rules)</h2>
            {saving && <span className="text-xs text-slate-400">saving…</span>}
          </div>

          {isAdmin() && (
            <div className="mt-3 grid gap-2 md:grid-cols-2">
              <input
                value={ruleSrc}
                onChange={(e) => setRuleSrc(e.target.value)}
                placeholder="src CIDR (optional)"
                className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
              />
              <input
                value={ruleDst}
                onChange={(e) => setRuleDst(e.target.value)}
                placeholder="dst CIDR (optional)"
                className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
              />
              <input
                value={ruleTable}
                onChange={(e) => setRuleTable(e.target.value)}
                placeholder="table (required)"
                className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
              />
              <input
                value={rulePrio}
                onChange={(e) => setRulePrio(e.target.value)}
                placeholder="priority (optional)"
                className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
              />
              <div className="md:col-span-2 flex justify-end">
                <button
                  onClick={addRule}
                  className="rounded-lg bg-mint/20 px-4 py-2 text-sm font-semibold text-mint hover:bg-mint/30"
                >
                  Add rule
                </button>
              </div>
            </div>
          )}

          <div className="mt-4 overflow-hidden rounded-xl border border-white/10">
            <table className="w-full text-sm">
              <thead className="bg-black/30 text-left text-xs uppercase tracking-wide text-slate-300">
                <tr>
                  <th className="px-4 py-3">Priority</th>
                  <th className="px-4 py-3">Src</th>
                  <th className="px-4 py-3">Dst</th>
                  <th className="px-4 py-3">Table</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {(cfg.rules ?? []).length === 0 && (
                  <tr>
                    <td className="px-4 py-4 text-slate-400" colSpan={5}>
                      No policy rules configured.
                    </td>
                  </tr>
                )}
                {(cfg.rules ?? []).map((r, idx) => (
                  <tr key={`${r.table}-${idx}`} className="border-t border-white/5">
                    <td className="px-4 py-3 text-slate-200">{r.priority ?? "auto"}</td>
                    <td className="px-4 py-3 text-slate-200">{r.src ?? "—"}</td>
                    <td className="px-4 py-3 text-slate-200">{r.dst ?? "—"}</td>
                    <td className="px-4 py-3 font-medium text-white">{r.table}</td>
                    <td className="px-4 py-3 text-right">
                      {isAdmin() ? (
                        <button
                          onClick={() => deleteRule(idx)}
                          className="rounded-md bg-white/5 px-3 py-1.5 text-xs text-slate-200 hover:bg-white/10"
                        >
                          Delete
                        </button>
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </Shell>
  );
}

