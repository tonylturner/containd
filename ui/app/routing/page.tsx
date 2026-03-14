"use client";

import { useEffect, useState } from "react";

import {
  api,
  isAdmin,
  type Gateway,
  type OSRoute,
  type OSRoutingSnapshot,
  type PolicyRule,
  type RoutingConfig,
  type StaticRoute,
} from "../../lib/api";
import { Shell } from "../../components/Shell";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import {
  GatewaysCard,
  OSRoutingCard,
  PolicyRulesCard,
  RoutingSetupCallout,
  StaticRoutesCard,
} from "./routing-sections";
import { effectiveDev, firstHostInCIDR, normCIDR, pickWanCIDR, pickWanIface } from "./routing-utils";

export default function RoutingPage() {
  const canEdit = isAdmin();
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

  async function save(next: RoutingConfig): Promise<{ ok: boolean; warning?: string }> {
    setError(null);
    setNotice(null);
    setSaving(true);
    const updated = await api.setRouting(next);
    setSaving(false);
    if (!updated.ok) {
      setError(updated.error || "Failed to save routing config.");
      return { ok: false };
    }
    setCfg({
      gateways: updated.data.gateways ?? [],
      routes: updated.data.routes ?? [],
      rules: updated.data.rules ?? [],
    });
    if (updated.warning) {
      setNotice(`Saved with warning: ${updated.warning}`);
    }
    return { ok: true, warning: updated.warning };
  }

  async function addGateway() {
    if (!canEdit) return;
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
    const result = await save(next);
    if (!result.ok) return;
    setGwName("");
    setGwAlias("");
    setGwAddr("");
    setGwIface("");
    setGwDesc("");
  }

  async function deleteGateway(idx: number) {
    if (!canEdit) return;
    const next: RoutingConfig = {
      gateways: (cfg.gateways ?? []).filter((_, i) => i !== idx),
      routes: cfg.routes ?? [],
      rules: cfg.rules ?? [],
    };
    await save(next);
  }

  function reconcileReplace() {
    if (!canEdit) return;
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
        if (!res.ok) {
          setError(res.error || "Failed to reconcile routing.");
          return;
        }
        await refresh();
        setNotice(res.warning ? `Routing reconciled with warning: ${res.warning}` : "Routing reconciled.");
      },
    });
  }

  async function addRoute() {
    if (!canEdit) return;
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
    const result = await save(next);
    if (!result.ok) return;
    setRouteDst("");
    setRouteGw("");
    setRouteIface("");
    setRouteTable("0");
    setRouteMetric("");
  }

  async function deleteRoute(idx: number) {
    if (!canEdit) return;
    const next: RoutingConfig = {
      gateways: cfg.gateways ?? [],
      routes: (cfg.routes ?? []).filter((_, i) => i !== idx),
      rules: cfg.rules ?? [],
    };
    await save(next);
  }

  async function addRule() {
    if (!canEdit) return;
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
    const result = await save(next);
    if (!result.ok) return;
    setRuleSrc("");
    setRuleDst("");
    setRuleTable("");
    setRulePrio("");
  }

  async function deleteRule(idx: number) {
    if (!canEdit) return;
    const next: RoutingConfig = {
      gateways: cfg.gateways ?? [],
      routes: cfg.routes ?? [],
      rules: (cfg.rules ?? []).filter((_, i) => i !== idx),
    };
    await save(next);
  }

  async function autoWanDefaultRoute() {
    if (!canEdit) return;
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

      const result = await save({ gateways: nextGateways, routes: nextRoutes, rules: cfg.rules ?? [] });
      if (!result.ok) return;
      setNotice(
        result.warning
          ? `Created/updated '${gwName}' (${inferredGw} via ${wanDev}) with warning: ${result.warning}`
          : `Created/updated '${gwName}' (${inferredGw} via ${wanDev}) and a default route. If LAN still can't reach the Internet, ensure there's an allow rule for LAN\u2192WAN and SNAT is enabled.`,
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

        const result = await save({ gateways: nextGateways, routes: nextRoutes, rules: cfg.rules ?? [] });
        if (!result.ok) return;
        setNotice(
          result.warning
            ? `Adopted OS default route via ${dev} \u2192 ${gwIP} with warning: ${result.warning}`
            : `Adopted OS default route via ${dev} \u2192 ${gwIP} into routing config.`,
        );
      },
    });
  }

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
          {canEdit && (
            <button
              onClick={autoWanDefaultRoute}
              className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110"
              title="Auto-create a WAN gateway and default route based on the WAN interface OS address (best-effort)."
            >
              Auto WAN default
            </button>
          )}
          {canEdit && (
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
      {!canEdit && (
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

      <RoutingSetupCallout
        hasConfig={(cfg.gateways ?? []).length > 0 || (cfg.routes ?? []).length > 0 || (cfg.rules ?? []).length > 0}
        hasOSDefault={!!(osRouting?.defaultRoute?.gateway && osRouting?.defaultRoute?.iface)}
        defaultIface={osRouting?.defaultRoute?.iface}
        defaultGateway={osRouting?.defaultRoute?.gateway}
        isAdmin={canEdit}
        onAdoptOSDefaultRoute={adoptOSDefaultRoute}
      />

      <OSRoutingCard osRouting={osRouting} isAdmin={canEdit} onAdoptOSDefaultRoute={adoptOSDefaultRoute} />

      <div className="grid gap-6 lg:grid-cols-2">
        <GatewaysCard
          gateways={cfg.gateways ?? []}
          isAdmin={canEdit}
          saving={saving}
          gwName={gwName}
          setGwName={setGwName}
          gwAlias={gwAlias}
          setGwAlias={setGwAlias}
          gwAddr={gwAddr}
          setGwAddr={setGwAddr}
          gwIface={gwIface}
          setGwIface={setGwIface}
          gwDesc={gwDesc}
          setGwDesc={setGwDesc}
          onAddGateway={addGateway}
          onDeleteGateway={deleteGateway}
        />

        <StaticRoutesCard
          gateways={cfg.gateways ?? []}
          routes={cfg.routes ?? []}
          isAdmin={canEdit}
          saving={saving}
          routeDst={routeDst}
          setRouteDst={setRouteDst}
          routeGw={routeGw}
          setRouteGw={setRouteGw}
          routeIface={routeIface}
          setRouteIface={setRouteIface}
          routeTable={routeTable}
          setRouteTable={setRouteTable}
          routeMetric={routeMetric}
          setRouteMetric={setRouteMetric}
          onAddRoute={addRoute}
          onDeleteRoute={deleteRoute}
          gatewayLabel={gatewayLabel}
        />

        <PolicyRulesCard
          rules={cfg.rules ?? []}
          isAdmin={canEdit}
          saving={saving}
          ruleSrc={ruleSrc}
          setRuleSrc={setRuleSrc}
          ruleDst={ruleDst}
          setRuleDst={setRuleDst}
          ruleTable={ruleTable}
          setRuleTable={setRuleTable}
          rulePrio={rulePrio}
          setRulePrio={setRulePrio}
          onAddRule={addRule}
          onDeleteRule={deleteRule}
        />
      </div>

      <ConfirmDialog {...confirm.props} />
    </Shell>
  );
}
