"use client";

import { useEffect, useState } from "react";

import {
  api,
  isAdmin,
  type Gateway,
  type Interface,
  type InterfaceState,
  type PolicyRule,
  type RoutingConfig,
  type StaticRoute,
} from "../../lib/api";
import { Shell } from "../../components/Shell";

function normCIDR(s: string) {
  return s.trim();
}

function ip4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map((p) => Number(p));
  if (nums.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return null;
  return ((nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]) >>> 0;
}

function intToIP4(n: number): string {
  const v = n >>> 0;
  return `${(v >>> 24) & 255}.${(v >>> 16) & 255}.${(v >>> 8) & 255}.${v & 255}`;
}

function maskFromPrefix(prefix: number): number | null {
  if (!Number.isFinite(prefix) || prefix < 0 || prefix > 32) return null;
  if (prefix === 0) return 0;
  return (0xffffffff << (32 - prefix)) >>> 0;
}

function firstHostInCIDR(cidr: string): string | null {
  const raw = cidr.trim();
  const slash = raw.lastIndexOf("/");
  if (slash <= 0) return null;
  const ip = raw.slice(0, slash);
  const pfx = Number(raw.slice(slash + 1));
  const ipInt = ip4ToInt(ip);
  const mask = maskFromPrefix(pfx);
  if (ipInt == null || mask == null) return null;
  const net = ipInt & mask;
  const first = (net + 1) >>> 0;
  return intToIP4(first);
}

function pickWanIface(ifs: Interface[]): Interface | null {
  const byName = ifs.find((i) => i.name === "wan");
  if (byName) return byName;
  const byZone = ifs.find((i) => (i.zone || "").toLowerCase() === "wan");
  return byZone ?? null;
}

function pickWanCIDR(state: InterfaceState | null): string | null {
  if (!state) return null;
  for (const addr of state.addrs || []) {
    const s = String(addr);
    if (!s.includes("/")) continue;
    if (s.includes(":")) continue;
    if (s.startsWith("169.254.")) continue;
    return s;
  }
  return null;
}

export default function RoutingPage() {
  const [cfg, setCfg] = useState<RoutingConfig>({ gateways: [], routes: [], rules: [] });
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [reconciling, setReconciling] = useState(false);

  const [gwName, setGwName] = useState("");
  const [gwAddr, setGwAddr] = useState("");
  const [gwIface, setGwIface] = useState("");
  const [gwDesc, setGwDesc] = useState("");

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
      gateways: r?.gateways ?? [],
      routes: r?.routes ?? [],
      rules: r?.rules ?? [],
    });
  }

  useEffect(() => {
    refresh();
  }, []);

  async function save(next: RoutingConfig) {
    setError(null);
    setNotice(null);
    setSaving(true);
    const updated = await api.setRouting(next);
    setSaving(false);
    if (!updated) {
      setError("Failed to save routing config.");
      return;
    }
    setCfg({
      gateways: updated.gateways ?? [],
      routes: updated.routes ?? [],
      rules: updated.rules ?? [],
    });
  }

  async function addGateway() {
    if (!isAdmin()) return;
    setError(null);
    if (!gwName.trim()) {
      setError("Gateway name is required.");
      return;
    }
    if (!gwAddr.trim()) {
      setError("Gateway address is required (IPv4).");
      return;
    }
    const nextGateway: Gateway = {
      name: gwName.trim(),
      address: gwAddr.trim(),
      iface: gwIface.trim() || undefined,
      description: gwDesc.trim() || undefined,
    };
    const next: RoutingConfig = {
      gateways: [...(cfg.gateways ?? []), nextGateway],
      routes: cfg.routes ?? [],
      rules: cfg.rules ?? [],
    };
    await save(next);
    setGwName("");
    setGwAddr("");
    setGwIface("");
    setGwDesc("");
  }

  async function deleteGateway(idx: number) {
    if (!isAdmin()) return;
    const next: RoutingConfig = {
      gateways: (cfg.gateways ?? []).filter((_, i) => i !== idx),
      routes: cfg.routes ?? [],
      rules: cfg.rules ?? [],
    };
    await save(next);
  }

  async function reconcileReplace() {
    if (!isAdmin()) return;
    setError(null);
    if (
      typeof window !== "undefined" &&
      !window.confirm(
        "Reconcile will REPLACE containd-managed routes/rules in the OS routing tables (best-effort). Continue?",
      )
    ) {
      return;
    }
    setReconciling(true);
    const res = await api.reconcileRoutingReplace();
    setReconciling(false);
    if (!res) {
      setError("Failed to reconcile routing.");
      return;
    }
    await refresh();
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
      gateways: cfg.gateways ?? [],
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
      gateways: cfg.gateways ?? [],
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
      gateways: cfg.gateways ?? [],
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
      gateways: cfg.gateways ?? [],
      routes: cfg.routes ?? [],
      rules: (cfg.rules ?? []).filter((_, i) => i !== idx),
    };
    await save(next);
  }

  async function autoWanDefaultRoute() {
    if (!isAdmin()) return;
    setError(null);
    setNotice(null);
    try {
      const [ifs, states] = await Promise.all([api.listInterfaces(), api.listInterfaceState()]);
      const wanIface = pickWanIface(ifs ?? []);
      if (!wanIface) {
        setError("Could not determine WAN interface (expected an interface named 'wan' or in zone 'wan').");
        return;
      }
      const wanState = (states ?? []).find((s) => s.name === wanIface.name) ?? null;
      const wanCIDR = pickWanCIDR(wanState);
      if (!wanCIDR) {
        setError(
          `Could not determine WAN IPv4 address for '${wanIface.name}'. If you're using DHCP in Docker, restart the container so Docker assigns an IP at startup.`,
        );
        return;
      }
      const inferredGw = firstHostInCIDR(wanCIDR);
      if (!inferredGw) {
        setError(`Could not infer a WAN gateway from '${wanCIDR}'.`);
        return;
      }

      const gwName = "wan-gw";
      const nextGateway: Gateway = {
        name: gwName,
        address: inferredGw,
        iface: wanIface.name,
        description: "Auto (WAN) from OS address",
      };
      const gateways = cfg.gateways ?? [];
      const existingGwIdx = gateways.findIndex((g) => g.name === gwName);
      const nextGateways =
        existingGwIdx >= 0 ? gateways.map((g, i) => (i === existingGwIdx ? nextGateway : g)) : [...gateways, nextGateway];

      const routes = cfg.routes ?? [];
      const isDefaultDst = (dst: string) => {
        const d = dst.trim().toLowerCase();
        return d === "default" || d === "0.0.0.0/0";
      };
      const existingDefaultIdx = routes.findIndex((r) => isDefaultDst(r.dst) && (r.table ?? 0) === 0);
      const nextDefault: StaticRoute = {
        dst: "default",
        gateway: gwName,
        iface: wanIface.name,
        table: 0,
      };
      const nextRoutes =
        existingDefaultIdx >= 0 ? routes.map((r, i) => (i === existingDefaultIdx ? nextDefault : r)) : [...routes, nextDefault];

      await save({ gateways: nextGateways, routes: nextRoutes, rules: cfg.rules ?? [] });
      setNotice(
        `Created/updated '${gwName}' (${inferredGw} via ${wanIface.name}) and a default route. If LAN still can't reach the Internet, ensure there's an allow rule for LAN→WAN and SNAT is enabled.`,
      );
    } catch (e) {
      setError(`Failed to auto-configure WAN default route: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  return (
    <Shell
      title="Routing"
      actions={
        <div className="flex items-center gap-2">
          {isAdmin() && (
            <button
              onClick={autoWanDefaultRoute}
              className="rounded-lg border border-mint/30 bg-mint/10 px-3 py-1.5 text-sm text-mint hover:bg-mint/15"
              title="Auto-create a WAN gateway and default route based on the WAN interface OS address (best-effort)."
            >
              Auto WAN default
            </button>
          )}
          {isAdmin() && (
            <button
              onClick={reconcileReplace}
              disabled={reconciling}
              className="rounded-lg border border-amber/30 bg-amber/10 px-3 py-1.5 text-sm text-amber hover:bg-amber/15 disabled:opacity-50"
              title="Reconcile routing rules (replace semantics for containd-managed routes/rules)"
            >
              {reconciling ? "Reconciling..." : "Reconcile"}
            </button>
          )}
          <button
            onClick={refresh}
            className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
          >
            Refresh
          </button>
        </div>
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

      {notice && (
        <div className="mb-4 rounded-xl border border-mint/30 bg-mint/10 px-4 py-3 text-sm text-mint">
          {notice}
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur lg:col-span-2">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-white">Gateways</h2>
              <div className="mt-1 text-xs text-slate-400">
                Named next-hops you can reference from routes (use the gateway name in the route gateway field).
              </div>
            </div>
            {saving && <span className="text-xs text-slate-400">saving…</span>}
          </div>

          {isAdmin() && (
            <div className="mt-3 grid gap-2 md:grid-cols-4">
              <input
                value={gwName}
                onChange={(e) => setGwName(e.target.value)}
                placeholder="name (e.g. isp1)"
                className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
              />
              <input
                value={gwAddr}
                onChange={(e) => setGwAddr(e.target.value)}
                placeholder="address (IPv4, e.g. 192.168.240.1)"
                className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
              />
              <input
                value={gwIface}
                onChange={(e) => setGwIface(e.target.value)}
                placeholder="iface (optional)"
                className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
              />
              <div className="flex gap-2">
                <input
                  value={gwDesc}
                  onChange={(e) => setGwDesc(e.target.value)}
                  placeholder="description (optional)"
                  className="flex-1 rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
                />
                <button
                  onClick={addGateway}
                  className="rounded-lg bg-mint/20 px-4 py-2 text-sm font-semibold text-mint hover:bg-mint/30"
                >
                  Add
                </button>
              </div>
            </div>
          )}

          <div className="mt-4 overflow-hidden rounded-xl border border-white/10">
            <table className="w-full text-sm">
              <thead className="bg-black/30 text-left text-xs uppercase tracking-wide text-slate-300">
                <tr>
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3">Address</th>
                  <th className="px-4 py-3">Iface</th>
                  <th className="px-4 py-3">Description</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {(cfg.gateways ?? []).length === 0 && (
                  <tr>
                    <td className="px-4 py-4 text-slate-400" colSpan={5}>
                      No gateways configured.
                    </td>
                  </tr>
                )}
                {(cfg.gateways ?? []).map((g, idx) => (
                  <tr key={`${g.name}-${idx}`} className="border-t border-white/5">
                    <td className="px-4 py-3 font-medium text-white">{g.name}</td>
                    <td className="px-4 py-3 text-slate-200">{g.address}</td>
                    <td className="px-4 py-3 text-slate-200">{g.iface || "—"}</td>
                    <td className="px-4 py-3 text-slate-200">{g.description || "—"}</td>
                    <td className="px-4 py-3 text-right">
                      {isAdmin() ? (
                        <button
                          onClick={() => deleteGateway(idx)}
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
              <div className="space-y-2">
                <input
                  value={routeGw}
                  onChange={(e) => setRouteGw(e.target.value)}
                  placeholder="gateway (IP or gateway name, optional)"
                  className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
                />
                {(cfg.gateways ?? []).length > 0 && (
                  <select
                    value=""
                    onChange={(e) => {
                      const v = e.target.value;
                      if (v) setRouteGw(v);
                    }}
                    className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
                  >
                    <option value="">Pick gateway…</option>
                    {(cfg.gateways ?? []).map((g) => (
                      <option key={g.name} value={g.name}>
                        {g.name} ({g.address})
                      </option>
                    ))}
                  </select>
                )}
              </div>
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
