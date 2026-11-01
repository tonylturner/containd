"use client";

import { useConfigLoad } from "../../lib/use-config-editor";

import { useAsyncRefresh } from "../../hooks/useAsyncRefresh";

import { useConfigForm } from "../../lib/use-config-form";
import { revisionError, ConfigEditNotice } from "../../lib/use-config-editor";

import { useConfigRefresh } from "../../lib/use-config-refresh";

import { useCallback, useState } from "react";

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
import { inferWanGateway, WAN_GATEWAY_NAME, wanGateway, withDefaultRoute } from "../../lib/wan-gateway";

export default function RoutingPage() {
  const canEdit = isAdmin();
  const { canSave, canSaveNow, loadError, checkLoaded } = useConfigLoad();
  const [osRouting, setOSRouting] = useState<OSRoutingSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [reconciling, setReconciling] = useState(false);
  const [interfaceStateUnavailable, setInterfaceStateUnavailable] = useState(false);
  const [detecting, setDetecting] = useState(false);

  const confirm = useConfirm();

  const form = useConfigForm({
    gwName: "", gwAlias: "", gwAddr: "", gwIface: "", gwDesc: "",
    routeDst: "", routeGw: "", routeIface: "", routeTable: "0", routeMetric: "",
    ruleSrc: "", ruleDst: "", ruleTable: "", rulePrio: "",
  }, { gateways: [], routes: [], rules: [] } as RoutingConfig);
  const cfg = form.context;
  const { readConfig: refreshForm } = form;
  const [gwName, setGwName] = form.field("gwName");
  const [gwAlias, setGwAlias] = form.field("gwAlias");
  const [gwAddr, setGwAddr] = form.field("gwAddr");
  const [gwIface, setGwIface] = form.field("gwIface");
  const [gwDesc, setGwDesc] = form.field("gwDesc");

  const [routeDst, setRouteDst] = form.field("routeDst");
  const [routeGw, setRouteGw] = form.field("routeGw");
  const [routeIface, setRouteIface] = form.field("routeIface");
  const [routeTable, setRouteTable] = form.field("routeTable");
  const [routeMetric, setRouteMetric] = form.field("routeMetric");

  const [ruleSrc, setRuleSrc] = form.field("ruleSrc");
  const [ruleDst, setRuleDst] = form.field("ruleDst");
  const [ruleTable, setRuleTable] = form.field("ruleTable");
  const [rulePrio, setRulePrio] = form.field("rulePrio");

  const gatewayLabel = (value?: string): string => {
    if (!value) return "\u2014";
    const match = (cfg.gateways ?? []).find((g) => g.name === value);
    if (!match) return value;
    return match.alias ? `${match.alias} (${match.name})` : match.name;
  };

  const { refresh } = useAsyncRefresh(useCallback(async ({ keepEdits = true }: { keepEdits?: boolean } = {}) => {
    const [rSnapshot, osr] = await Promise.all([api.getRouting(), api.getOSRouting()]);
    const r = rSnapshot?.data;
    if (!checkLoaded(r)) return;
    setOSRouting(osr);
    refreshForm({ data: r, revision: rSnapshot?.revision ?? "" }, keepEdits);
  }, [refreshForm, checkLoaded]));

  useConfigRefresh(refresh);

  async function save(update: (current: RoutingConfig) => RoutingConfig, fields: (keyof typeof form.editor.cfg.fields)[] = []): Promise<{ ok: boolean; warning?: string; revision?: string }> {
    if (!canEdit || !canSaveNow()) return { ok: false };
    setError(null);
    setNotice(null);
    setSaving(true);
    const updated = await form.write((base, current) => api.setRouting(base, update(current)), fields, { context: (_view, data) => data });
    setSaving(false);
    if (!updated.ok) {
      setError(revisionError(updated));
      return { ok: false };
    }
    setNotice(updated.warning ? `Routing staged — commit to apply. Warning: ${updated.warning}` : "Routing staged — commit to apply.");
    return { ok: true, warning: updated.warning, revision: updated.revision };
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
    await save(current => ({
      ...current,
      gateways: [...(current.gateways ?? []), nextGateway],
      routes: current.routes ?? [],
      rules: current.rules ?? [],
    }), ["gwName", "gwAlias", "gwAddr", "gwIface", "gwDesc"]);
  }

  async function deleteGateway(idx: number) {
    if (!canEdit) return;
    const removed = cfg.gateways?.[idx]?.name;
    await save(current => ({
      ...current,
      gateways: (current.gateways ?? []).filter(row => row.name !== removed),
      routes: current.routes ?? [],
      rules: current.rules ?? [],
    }));
  }

  function reconcileReplace() {
    if (!canEdit) return;
    setError(null);
    confirm.open({
      title: "Reconcile Routing",
      message:
        "Live reconcile reapplies running config and will REPLACE containd-managed routes/rules in the OS routing tables (best-effort). Continue?",
      variant: "warning",
      confirmLabel: "Reconcile",
      onConfirm: async () => {
        if (!canSaveNow()) return;
        setReconciling(true);
        // Runtime operations cannot acknowledge or rebase a retained draft.
        const res = await api.reconcileRoutingReplace();
        setReconciling(false);
        if (!res.ok) {
          setError(res.error);
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
    const dst = routeDst.trim();
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
    await save(current => ({
      ...current,
      gateways: current.gateways ?? [],
      routes: [...(current.routes ?? []), nextRoute],
      rules: current.rules ?? [],
    }), ["routeDst", "routeGw", "routeIface", "routeTable", "routeMetric"]);
  }

  async function deleteRoute(idx: number) {
    if (!canEdit) return;
    await save(current => ({
      ...current,
      gateways: current.gateways ?? [],
      routes: (current.routes ?? []).filter((_, i) => i !== idx),
      rules: current.rules ?? [],
    }));
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
      src: ruleSrc.trim() || undefined,
      dst: ruleDst.trim() || undefined,
    };
    await save(current => ({
      ...current,
      gateways: current.gateways ?? [],
      routes: current.routes ?? [],
      rules: [...(current.rules ?? []), nextRule],
    }), ["ruleSrc", "ruleDst", "ruleTable", "rulePrio"]);
  }

  async function deleteRule(idx: number) {
    if (!canEdit) return;
    await save(current => ({
      ...current,
      gateways: current.gateways ?? [],
      routes: current.routes ?? [],
      rules: (current.rules ?? []).filter((_, i) => i !== idx),
    }));
  }

  async function autoWanDefaultRoute() {
    if (!canEdit) return;
    setError(null);
    setNotice(null);
    try {
      const [ifsSnapshot, states] = await Promise.all([api.listInterfaces(), api.listInterfaceState()]);
      const ifs = ifsSnapshot?.data ?? null;
      setInterfaceStateUnavailable(states === null);
      if (states === null) return;
      if (ifs === null) {
        setError("Interface configuration unavailable.");
        return;
      }
      const inferred = inferWanGateway(ifs, states);
      if (!inferred.ok) {
        setError(inferred.error);
        return;
      }
      const { address, device } = inferred.wan;
      const result = await save(current => withDefaultRoute(current, wanGateway(inferred.wan)));
      if (!result.ok) return;
      setNotice(
        result.warning
          ? `Gateway and default route staged — commit to apply. '${WAN_GATEWAY_NAME}' (${address} via ${device}) with warning: ${result.warning}`
          : `Gateway and default route staged — commit to apply. '${WAN_GATEWAY_NAME}' (${address} via ${device}) and a default route. If LAN still can't reach the Internet, ensure there's an allow rule for LAN\u2192WAN and SNAT is enabled.`,
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
        if (!canSaveNow()) return;
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

        const result = await save(
          current => withDefaultRoute(current, {
            name: "os-default-gw",
            address: gwIP,
            iface: dev,
            description: "Adopted from OS default route",
          }),
        );
        if (!result.ok) return;
        setNotice(
          result.warning
            ? `Default route staged — commit to apply. OS route via ${dev} \u2192 ${gwIP} with warning: ${result.warning}`
            : `Default route staged — commit to apply. OS route via ${dev} \u2192 ${gwIP} into routing config.`,
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
            className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
            title="Reload OS routing table snapshot"
          >
            {detecting ? "Detecting..." : "Detect from OS"}
          </button>
          {canEdit && (
            <button
              onClick={autoWanDefaultRoute}
              disabled={!canSave}
              className="rounded-xs bg-(--amber) px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110"
              title="Auto-create a WAN gateway and default route based on the WAN interface OS address (best-effort)."
            >
              Auto WAN default
            </button>
          )}
          {canEdit && (
            <button
              onClick={reconcileReplace}
              disabled={reconciling}
              className="rounded-xs border px-3 py-1.5 text-sm transition-ui disabled:opacity-50"
              title="Reconcile routing rules (replace semantics for containd-managed routes/rules)"
            >
              {reconciling ? "Reconciling..." : "Reconcile live"}
            </button>
          )}
          <button
            onClick={() => refresh({ keepEdits: false })}
            className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
          >
            Refresh
          </button>
        </div>
      }
    >
      {loadError && <p role="alert" className="mb-4 text-sm text-red-400">{loadError}</p>}
      <ConfigEditNotice superseded={form.editor.superseded} {...form.conflictProps} onReload={() => refresh({ keepEdits: false })} />
      {!canEdit && (
        <div className="mb-4 rounded-xs border bg-(--surface) px-4 py-3 text-sm text-(--text)">
          View-only mode: configuration changes are disabled.
        </div>
      )}

      {interfaceStateUnavailable && (
        <div role="status" className="mb-4 rounded-xs border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          <p>Interface runtime state unavailable — the engine could not be reached. Auto WAN setup cannot determine the WAN address; no routing changes were staged.</p>
          <button onClick={autoWanDefaultRoute} className="mt-2 rounded-xs border border-red-500/30 px-3 py-1">Retry</button>
        </div>
      )}

      {error && (
        <div className="mb-4 rounded-xs border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {notice && (
        <div className="mb-4 rounded-xs border px-4 py-3 text-sm text-(--amber)">
          {notice}
        </div>
      )}

      <fieldset disabled={!canSave} className="min-w-0">
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

      </fieldset>
      <ConfirmDialog {...confirm.props} />
    </Shell>
  );
}
