"use client";

import { useEffect, useState } from "react";

import {
  api,
  isAdmin,
  type Gateway,
  type Interface,
  type InterfaceState,
  type OSRoute,
  type OSRoutingSnapshot,
  type PolicyRule,
  type RoutingConfig,
  type StaticRoute,
} from "../../lib/api";
import { Shell } from "../../components/Shell";
import { InfoTip } from "../../components/InfoTip";
import { Card } from "../../components/Card";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";

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

function effectiveDev(i: Interface | null): string {
  if (!i) return "";
  return (i.device || i.name || "").trim();
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
  const [osRouting, setOSRouting] = useState<OSRoutingSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [reconciling, setReconciling] = useState(false);
  const [detecting, setDetecting] = useState(false);

  const confirm = useConfirm();

  const [gwName, setGwName] = useState("");
  const [gwAlias, setGwAlias] = useState("");
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

  const gatewayLabel = (value?: string): string => {
    if (!value) return "\u2014";
    const match = (cfg.gateways ?? []).find((g) => g.name === value);
    if (!match) return value;
    return match.alias ? `${match.alias} (${match.name})` : match.name;
  };

  async function refresh() {
    const [r, osr] = await Promise.all([api.getRouting(), api.getOSRouting()]);
    setCfg({ gateways: r?.gateways ?? [], routes: r?.routes ?? [], rules: r?.rules ?? [] });
    setOSRouting(osr);
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
      alias: gwAlias.trim() || undefined,
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
    setGwAlias("");
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

  function reconcileReplace() {
    if (!isAdmin()) return;
    setError(null);
    confirm.open({
      title: "Reconcile Routing",
      message:
        "Reconcile will REPLACE containd-managed routes/rules in the OS routing tables (best-effort). Continue?",
      variant: "warning",
      confirmLabel: "Reconcile",
      onConfirm: async () => {
        setReconciling(true);
        const res = await api.reconcileRoutingReplace();
        setReconciling(false);
        if (!res) {
          setError("Failed to reconcile routing.");
          return;
        }
        await refresh();
      },
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
      const wanDev = effectiveDev(wanIface);
      const wanState = (states ?? []).find((s) => s.name === wanDev) ?? null;
      const wanCIDR = pickWanCIDR(wanState);
      if (!wanCIDR) {
        setError(
          `Could not determine WAN IPv4 address for '${wanDev}'. If you're using DHCP in Docker, restart the container so Docker assigns an IP at startup.`,
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
        iface: wanDev,
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
        iface: wanDev,
        table: 0,
      };
      const nextRoutes =
        existingDefaultIdx >= 0 ? routes.map((r, i) => (i === existingDefaultIdx ? nextDefault : r)) : [...routes, nextDefault];

      await save({ gateways: nextGateways, routes: nextRoutes, rules: cfg.rules ?? [] });
      setNotice(
        `Created/updated '${gwName}' (${inferredGw} via ${wanDev}) and a default route. If LAN still can't reach the Internet, ensure there's an allow rule for LAN\u2192WAN and SNAT is enabled.`,
      );
    } catch (e) {
      setError(`Failed to auto-configure WAN default route: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  async function refreshOSRouting() {
    setDetecting(true);
    const osr = await api.getOSRouting();
    setDetecting(false);
    setOSRouting(osr);
    if (!osr) {
      setError("Failed to load OS routing table (not supported or API unavailable).");
    }
  }

  function adoptOSDefaultRoute() {
    if (!isAdmin()) return;
    setError(null);
    setNotice(null);
    confirm.open({
      title: "Adopt OS Default Route",
      message:
        "Adopt the current OS default route into containd config (creates/updates a gateway + default route)?",
      confirmLabel: "Adopt",
      onConfirm: async () => {
        const def: OSRoute | undefined = osRouting?.defaultRoute;
        if (!def || !def.gateway) {
          setError("No OS default route with a gateway was detected.");
          return;
        }
        const gwIP = def.gateway.trim();
        const dev = (def.iface || "").trim();
        if (!gwIP || !dev) {
          setError("Detected default route is missing a gateway or interface.");
          return;
        }

        const gwName = "os-default-gw";
        const nextGateway: Gateway = {
          name: gwName,
          address: gwIP,
          iface: dev,
          description: "Adopted from OS default route",
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
        const nextDefault: StaticRoute = { dst: "default", gateway: gwName, iface: dev, table: 0 };
        const nextRoutes =
          existingDefaultIdx >= 0 ? routes.map((r, i) => (i === existingDefaultIdx ? nextDefault : r)) : [...routes, nextDefault];

        await save({ gateways: nextGateways, routes: nextRoutes, rules: cfg.rules ?? [] });
        setNotice(`Adopted OS default route via ${dev} \u2192 ${gwIP} into routing config.`);
      },
    });
  }

  const inputClass =
    "mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none";

  return (
    <Shell
      title="Routing"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={refreshOSRouting}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
            title="Reload OS routing table snapshot"
          >
            {detecting ? "Detecting..." : "Detect from OS"}
          </button>
          {isAdmin() && (
            <button
              onClick={autoWanDefaultRoute}
              className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110"
              title="Auto-create a WAN gateway and default route based on the WAN interface OS address (best-effort)."
            >
              Auto WAN default
            </button>
          )}
          {isAdmin() && (
            <button
              onClick={reconcileReplace}
              disabled={reconciling}
              className="rounded-sm border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-sm text-amber-400 transition-ui hover:bg-amber-500/15 disabled:opacity-50"
              title="Reconcile routing rules (replace semantics for containd-managed routes/rules)"
            >
              {reconciling ? "Reconciling..." : "Reconcile"}
            </button>
          )}
          <button
            onClick={refresh}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
          >
            Refresh
          </button>
        </div>
      }
    >
      {!isAdmin() && (
        <div className="mb-4 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3 text-sm text-[var(--text)]">
          View-only mode: configuration changes are disabled.
        </div>
      )}

      {error && (
        <div className="mb-4 rounded-sm border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {notice && (
        <div className="mb-4 rounded-sm border border-amber-500/20 bg-amber-500/[0.1] px-4 py-3 text-sm text-[var(--amber)]">
          {notice}
        </div>
      )}

      {(() => {
        const hasConfig =
          (cfg.gateways ?? []).length > 0 || (cfg.routes ?? []).length > 0 || (cfg.rules ?? []).length > 0;
        const hasOSDefault = !!(osRouting?.defaultRoute?.gateway && osRouting?.defaultRoute?.iface);
        if (hasConfig || !hasOSDefault) return null;
        return (
          <div className="mb-6 rounded-sm border border-amber-500/20 bg-amber-500/[0.1] p-5 shadow-card backdrop-blur">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="text-sm font-semibold text-[var(--text)]">Routing not configured yet</div>
                <div className="mt-1 text-xs text-[var(--text)]">
                  The kernel already has a working default route (
                  <span className="font-semibold">{osRouting?.defaultRoute?.iface}</span> →{" "}
                  <span className="font-semibold">{osRouting?.defaultRoute?.gateway}</span>). Adopt it into containd so
                  routing/NAT policies can be applied consistently.
                </div>
              </div>
              {isAdmin() ? (
                <button
                  onClick={adoptOSDefaultRoute}
                  className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110"
                >
                  Adopt OS default route
                </button>
              ) : (
                <div className="text-xs text-[var(--text)]">Admin required to adopt routing.</div>
              )}
            </div>
          </div>
        );
      })()}

      <Card padding="lg" className="mb-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-[var(--text)]">Detect from OS</h2>
            <div className="mt-1 text-xs text-[var(--text-muted)]">
              Shows the current kernel routing table. This is useful in Docker labs where the OS already has a working default
              route, but your configured routing is still empty.
            </div>
          </div>
          {isAdmin() && (
            <button
              onClick={adoptOSDefaultRoute}
              disabled={!osRouting?.defaultRoute?.gateway || !osRouting?.defaultRoute?.iface}
              className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50"
              title="Create a gateway + default route in config from the detected OS default route"
            >
              Adopt default route
            </button>
          )}
        </div>

        {osRouting?.routes?.length ? (
          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-sm text-[var(--text)]">
              <thead className="bg-[var(--surface)] text-left text-xs uppercase tracking-wide text-[var(--text)]">
                <tr>
                  <th className="px-3 py-2">Destination</th>
                  <th className="px-3 py-2">Gateway</th>
                  <th className="px-3 py-2">Iface</th>
                  <th className="px-3 py-2">Metric</th>
                </tr>
              </thead>
              <tbody>
                {osRouting.routes.map((r, idx) => (
                  <tr key={idx} className="table-row-hover transition-ui border-t border-amber-500/[0.1]">
                    <td className="px-3 py-2 font-medium text-[var(--text)]">{r.dst || "\u2014"}</td>
                    <td className="px-3 py-2">{r.gateway || "\u2014"}</td>
                    <td className="px-3 py-2">{r.iface || "\u2014"}</td>
                    <td className="px-3 py-2">{typeof r.metric === "number" ? String(r.metric) : "\u2014"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {osRouting.defaultRoute?.gateway && osRouting.defaultRoute?.iface && (
              <div className="mt-3 text-xs text-[var(--text-muted)]">
                Detected default: <span className="text-[var(--text)]">{osRouting.defaultRoute.iface}</span> →{" "}
                <span className="text-[var(--text)]">{osRouting.defaultRoute.gateway}</span>
              </div>
            )}
          </div>
        ) : (
          <div className="mt-4 text-sm text-[var(--text)]">
            No OS routes detected (or not supported in this environment). Click <span className="font-semibold">Detect from OS</span>{" "}
            to refresh.
          </div>
        )}
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card padding="lg" className="lg:col-span-2">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-[var(--text)]">Gateways</h2>
              <div className="mt-1 text-xs text-[var(--text-muted)]">
                Named next-hops you can reference from routes (use the gateway name in the route gateway field).
              </div>
            </div>
            {saving && <span className="text-xs text-[var(--text-muted)]">saving\u2026</span>}
          </div>

          {isAdmin() && (
            <details className="mt-3 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3">
              <summary className="cursor-pointer text-sm text-[var(--text)]">
                Add gateway (advanced)
              </summary>
              <div className="mt-3 grid gap-2 md:grid-cols-5">
                <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
                  Name
                  <InfoTip label="Human-friendly name used by routes (e.g. isp1)." />
                  <input
                    value={gwName}
                    onChange={(e) => setGwName(e.target.value)}
                    placeholder="isp1"
                    className={inputClass}
                  />
                </label>
                <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
                  Alias
                  <InfoTip label="Optional display name shown in selectors." />
                  <input
                    value={gwAlias}
                    onChange={(e) => setGwAlias(e.target.value)}
                    placeholder="primary ISP"
                    className={inputClass}
                  />
                </label>
                <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
                  Address
                  <InfoTip label="IPv4 address of the next-hop gateway." />
                  <input
                    value={gwAddr}
                    onChange={(e) => setGwAddr(e.target.value)}
                    placeholder="192.168.240.1"
                    className={inputClass}
                  />
                </label>
                <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
                  Interface
                  <InfoTip label="Optional interface to bind this gateway to." />
                  <input
                    value={gwIface}
                    onChange={(e) => setGwIface(e.target.value)}
                    placeholder="wan"
                    className={inputClass}
                  />
                </label>
                <div className="flex gap-2 md:col-span-1">
                  <label className="flex-1 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                    Description
                    <input
                      value={gwDesc}
                      onChange={(e) => setGwDesc(e.target.value)}
                      placeholder="primary ISP"
                      className={inputClass}
                    />
                  </label>
                  <button
                    onClick={addGateway}
                    className="rounded-sm bg-[var(--amber)] px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110"
                  >
                    Add
                  </button>
                </div>
              </div>
            </details>
          )}

          <div className="mt-4 overflow-hidden rounded-sm border border-amber-500/[0.15]">
            <table className="w-full text-sm">
              <thead className="bg-[var(--surface)] text-left text-xs uppercase tracking-wide text-[var(--text)]">
                <tr>
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3">Alias</th>
                  <th className="px-4 py-3">Address</th>
                  <th className="px-4 py-3">Iface</th>
                  <th className="px-4 py-3">Description</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {(cfg.gateways ?? []).length === 0 && (
                  <tr>
                    <td className="px-4 py-4 text-[var(--text-muted)]" colSpan={6}>
                      No gateways configured. Add a default gateway to enable outbound routing.
                    </td>
                  </tr>
                )}
                {(cfg.gateways ?? []).map((g, idx) => (
                  <tr key={`${g.name}-${idx}`} className="table-row-hover transition-ui border-t border-amber-500/[0.1]">
                    <td className="px-4 py-3 font-medium text-[var(--text)]">{g.name}</td>
                    <td className="px-4 py-3 text-[var(--text)]">{g.alias || "\u2014"}</td>
                    <td className="px-4 py-3 text-[var(--text)]">{g.address}</td>
                    <td className="px-4 py-3 text-[var(--text)]">{g.iface || "\u2014"}</td>
                    <td className="px-4 py-3 text-[var(--text)]">{g.description || "\u2014"}</td>
                    <td className="px-4 py-3 text-right">
                      {isAdmin() ? (
                        <button
                          onClick={() => deleteGateway(idx)}
                          className="rounded-md px-3 py-1.5 text-xs text-red-400 transition-ui hover:bg-red-500/10"
                        >
                          Delete
                        </button>
                      ) : (
                        <span className="text-[var(--text-dim)]">\u2014</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        <Card padding="lg">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-[var(--text)]">Static routes</h2>
            {saving && <span className="text-xs text-[var(--text-muted)]">saving\u2026</span>}
          </div>

          {isAdmin() && (
            <details className="mt-3 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3">
              <summary className="cursor-pointer text-sm text-[var(--text)]">
                Add static route (advanced)
              </summary>
              <div className="mt-3 grid gap-2 md:grid-cols-2">
                <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
                  Destination
                  <InfoTip label="CIDR or default. Example: 0.0.0.0/0 or 10.0.0.0/24." />
                  <input
                    value={routeDst}
                    onChange={(e) => setRouteDst(e.target.value)}
                    placeholder="dst (CIDR or default)"
                    className={inputClass}
                  />
                </label>
                <div className="space-y-2">
                  <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
                    Gateway
                    <InfoTip label="Gateway IP or gateway name. Optional if iface is set." />
                    <input
                      value={routeGw}
                      onChange={(e) => setRouteGw(e.target.value)}
                      placeholder="gateway (IP or gateway name, optional)"
                      className={inputClass}
                    />
                  </label>
                  {(cfg.gateways ?? []).length > 0 && (
                    <select
                      value=""
                      onChange={(e) => {
                        const v = e.target.value;
                        if (v) setRouteGw(v);
                      }}
                      className="w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                    >
                      <option value="">Pick gateway\u2026</option>
                      {(cfg.gateways ?? []).map((g) => (
                        <option key={g.name} value={g.name}>
                          {g.alias ? `${g.alias} (${g.name})` : g.name} ({g.address})
                        </option>
                      ))}
                    </select>
                  )}
                </div>
                <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
                  Interface
                  <InfoTip label="Logical or OS device (optional)." />
                  <input
                    value={routeIface}
                    onChange={(e) => setRouteIface(e.target.value)}
                    placeholder="iface (logical or OS dev, optional)"
                    className={inputClass}
                  />
                </label>
                <div className="grid grid-cols-2 gap-2">
                  <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
                    Table
                    <InfoTip label="Routing table (0 = main)." />
                    <input
                      value={routeTable}
                      onChange={(e) => setRouteTable(e.target.value)}
                      placeholder="table (0=main)"
                      className={inputClass}
                    />
                  </label>
                  <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
                    Metric
                    <InfoTip label="Optional route priority (lower wins)." />
                    <input
                      value={routeMetric}
                      onChange={(e) => setRouteMetric(e.target.value)}
                      placeholder="metric (optional)"
                      className={inputClass}
                    />
                  </label>
                </div>
                <div className="md:col-span-2 flex justify-end">
                  <button
                    onClick={addRoute}
                    className="rounded-sm bg-[var(--amber)] px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110"
                  >
                    Add route
                  </button>
                </div>
              </div>
            </details>
          )}

          <div className="mt-4 overflow-hidden rounded-sm border border-amber-500/[0.15]">
            <table className="w-full text-sm">
              <thead className="bg-[var(--surface)] text-left text-xs uppercase tracking-wide text-[var(--text)]">
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
                    <td className="px-4 py-4 text-[var(--text-muted)]" colSpan={6}>
                      No static routes configured. Static routes direct traffic to specific subnets via a gateway.
                    </td>
                  </tr>
                )}
                {(cfg.routes ?? []).map((r, idx) => (
                  <tr key={`${r.dst}-${idx}`} className="table-row-hover transition-ui border-t border-amber-500/[0.1]">
                    <td className="px-4 py-3 font-medium text-[var(--text)]">{r.dst}</td>
                    <td className="px-4 py-3 text-[var(--text)]">{gatewayLabel(r.gateway)}</td>
                    <td className="px-4 py-3 text-[var(--text)]">{r.iface ?? "\u2014"}</td>
                    <td className="px-4 py-3 text-[var(--text)]">{r.table ?? 0}</td>
                    <td className="px-4 py-3 text-[var(--text)]">{r.metric ?? "\u2014"}</td>
                    <td className="px-4 py-3 text-right">
                      {isAdmin() ? (
                        <button
                          onClick={() => deleteRoute(idx)}
                          className="rounded-md px-3 py-1.5 text-xs text-red-400 transition-ui hover:bg-red-500/10"
                        >
                          Delete
                        </button>
                      ) : (
                        <span className="text-[var(--text-dim)]">\u2014</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        <Card padding="lg">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-[var(--text)]">Policy-based routing (ip rules)</h2>
            {saving && <span className="text-xs text-[var(--text-muted)]">saving\u2026</span>}
          </div>

          {isAdmin() && (
            <details className="mt-3 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3">
              <summary className="cursor-pointer text-sm text-[var(--text)]">
                Add policy rule (advanced)
              </summary>
              <div className="mt-3 grid gap-2 md:grid-cols-2">
                <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
                  Source CIDR
                  <InfoTip label="Optional source match." />
                  <input
                    value={ruleSrc}
                    onChange={(e) => setRuleSrc(e.target.value)}
                    placeholder="src CIDR (optional)"
                    className={inputClass}
                  />
                </label>
                <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
                  Destination CIDR
                  <InfoTip label="Optional destination match." />
                  <input
                    value={ruleDst}
                    onChange={(e) => setRuleDst(e.target.value)}
                    placeholder="dst CIDR (optional)"
                    className={inputClass}
                  />
                </label>
                <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
                  Table
                  <InfoTip label="Routing table to use when rule matches (required)." />
                  <input
                    value={ruleTable}
                    onChange={(e) => setRuleTable(e.target.value)}
                    placeholder="table (required)"
                    className={inputClass}
                  />
                </label>
                <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
                  Priority
                  <InfoTip label="Optional priority; lower wins." />
                  <input
                    value={rulePrio}
                    onChange={(e) => setRulePrio(e.target.value)}
                    placeholder="priority (optional)"
                    className={inputClass}
                  />
                </label>
                <div className="md:col-span-2 flex justify-end">
                  <button
                    onClick={addRule}
                    className="rounded-sm bg-[var(--amber)] px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110"
                  >
                    Add rule
                  </button>
                </div>
              </div>
            </details>
          )}

          <div className="mt-4 overflow-hidden rounded-sm border border-amber-500/[0.15]">
            <table className="w-full text-sm">
              <thead className="bg-[var(--surface)] text-left text-xs uppercase tracking-wide text-[var(--text)]">
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
                    <td className="px-4 py-4 text-[var(--text-muted)]" colSpan={5}>
                      No policy rules configured.
                    </td>
                  </tr>
                )}
                {(cfg.rules ?? []).map((r, idx) => (
                  <tr key={`${r.table}-${idx}`} className="table-row-hover transition-ui border-t border-amber-500/[0.1]">
                    <td className="px-4 py-3 text-[var(--text)]">{r.priority ?? "auto"}</td>
                    <td className="px-4 py-3 text-[var(--text)]">{r.src ?? "\u2014"}</td>
                    <td className="px-4 py-3 text-[var(--text)]">{r.dst ?? "\u2014"}</td>
                    <td className="px-4 py-3 font-medium text-[var(--text)]">{r.table}</td>
                    <td className="px-4 py-3 text-right">
                      {isAdmin() ? (
                        <button
                          onClick={() => deleteRule(idx)}
                          className="rounded-md px-3 py-1.5 text-xs text-red-400 transition-ui hover:bg-red-500/10"
                        >
                          Delete
                        </button>
                      ) : (
                        <span className="text-[var(--text-dim)]">\u2014</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>

      <ConfirmDialog {...confirm.props} />
    </Shell>
  );
}
