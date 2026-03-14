"use client";

import type { Dispatch, SetStateAction } from "react";

import type { Gateway, OSRoutingSnapshot, PolicyRule, StaticRoute } from "../../lib/api";
import { Card } from "../../components/Card";
import { InfoTip } from "../../components/InfoTip";

type StringSetter = Dispatch<SetStateAction<string>>;

const INPUT_CLASS =
  "mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none";

type RoutingSetupCalloutProps = {
  hasConfig: boolean;
  hasOSDefault: boolean;
  defaultIface?: string;
  defaultGateway?: string;
  isAdmin: boolean;
  onAdoptOSDefaultRoute: () => void;
};

export function RoutingSetupCallout({
  hasConfig,
  hasOSDefault,
  defaultIface,
  defaultGateway,
  isAdmin,
  onAdoptOSDefaultRoute,
}: RoutingSetupCalloutProps) {
  if (hasConfig || !hasOSDefault) return null;
  return (
    <div className="mb-6 rounded-sm border border-amber-500/20 bg-amber-500/[0.1] p-5 shadow-card backdrop-blur">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-[var(--text)]">Routing not configured yet</div>
          <div className="mt-1 text-xs text-[var(--text)]">
            The kernel already has a working default route (
            <span className="font-semibold">{defaultIface}</span> →{" "}
            <span className="font-semibold">{defaultGateway}</span>). Adopt it into containd so routing/NAT policies can
            be applied consistently.
          </div>
        </div>
        {isAdmin ? (
          <button
            onClick={onAdoptOSDefaultRoute}
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
}

type OSRoutingCardProps = {
  osRouting: OSRoutingSnapshot | null;
  isAdmin: boolean;
  onAdoptOSDefaultRoute: () => void;
};

export function OSRoutingCard({ osRouting, isAdmin, onAdoptOSDefaultRoute }: OSRoutingCardProps) {
  return (
    <Card padding="lg" className="mb-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-[var(--text)]">Detect from OS</h2>
          <div className="mt-1 text-xs text-[var(--text-muted)]">
            Shows the current kernel routing table. This is useful in Docker labs where the OS already has a working
            default route, but your configured routing is still empty.
          </div>
        </div>
        {isAdmin && (
          <button
            onClick={onAdoptOSDefaultRoute}
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
  );
}

type GatewaysCardProps = {
  gateways: Gateway[];
  isAdmin: boolean;
  saving: boolean;
  gwName: string;
  setGwName: StringSetter;
  gwAlias: string;
  setGwAlias: StringSetter;
  gwAddr: string;
  setGwAddr: StringSetter;
  gwIface: string;
  setGwIface: StringSetter;
  gwDesc: string;
  setGwDesc: StringSetter;
  onAddGateway: () => void;
  onDeleteGateway: (idx: number) => void;
};

export function GatewaysCard(props: GatewaysCardProps) {
  const {
    gateways,
    isAdmin,
    saving,
    gwName,
    setGwName,
    gwAlias,
    setGwAlias,
    gwAddr,
    setGwAddr,
    gwIface,
    setGwIface,
    gwDesc,
    setGwDesc,
    onAddGateway,
    onDeleteGateway,
  } = props;

  return (
    <Card padding="lg" className="lg:col-span-2">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-[var(--text)]">Gateways</h2>
          <div className="mt-1 text-xs text-[var(--text-muted)]">
            Named next-hops you can reference from routes (use the gateway name in the route gateway field).
          </div>
        </div>
        {saving && <span className="text-xs text-[var(--text-muted)]">saving…</span>}
      </div>

      {isAdmin && (
        <details className="mt-3 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3">
          <summary className="cursor-pointer text-sm text-[var(--text)]">Add gateway (advanced)</summary>
          <div className="mt-3 grid gap-2 md:grid-cols-5">
            <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
              Name
              <InfoTip label="Human-friendly name used by routes (e.g. isp1)." />
              <input value={gwName} onChange={(e) => setGwName(e.target.value)} placeholder="isp1" className={INPUT_CLASS} />
            </label>
            <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
              Alias
              <InfoTip label="Optional display name shown in selectors." />
              <input value={gwAlias} onChange={(e) => setGwAlias(e.target.value)} placeholder="primary ISP" className={INPUT_CLASS} />
            </label>
            <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
              Address
              <InfoTip label="IPv4 address of the next-hop gateway." />
              <input value={gwAddr} onChange={(e) => setGwAddr(e.target.value)} placeholder="192.168.240.1" className={INPUT_CLASS} />
            </label>
            <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
              Interface
              <InfoTip label="Optional interface to bind this gateway to." />
              <input value={gwIface} onChange={(e) => setGwIface(e.target.value)} placeholder="wan" className={INPUT_CLASS} />
            </label>
            <div className="flex gap-2 md:col-span-1">
              <label className="flex-1 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                Description
                <input value={gwDesc} onChange={(e) => setGwDesc(e.target.value)} placeholder="primary ISP" className={INPUT_CLASS} />
              </label>
              <button
                onClick={onAddGateway}
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
            {gateways.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-[var(--text-muted)]" colSpan={6}>
                  No gateways configured. Add a default gateway to enable outbound routing.
                </td>
              </tr>
            )}
            {gateways.map((g, idx) => (
              <tr key={`${g.name}-${idx}`} className="table-row-hover transition-ui border-t border-amber-500/[0.1]">
                <td className="px-4 py-3 font-medium text-[var(--text)]">{g.name}</td>
                <td className="px-4 py-3 text-[var(--text)]">{g.alias || "\u2014"}</td>
                <td className="px-4 py-3 text-[var(--text)]">{g.address}</td>
                <td className="px-4 py-3 text-[var(--text)]">{g.iface || "\u2014"}</td>
                <td className="px-4 py-3 text-[var(--text)]">{g.description || "\u2014"}</td>
                <td className="px-4 py-3 text-right">
                  {isAdmin ? (
                    <button
                      onClick={() => onDeleteGateway(idx)}
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
  );
}

type StaticRoutesCardProps = {
  gateways: Gateway[];
  routes: StaticRoute[];
  isAdmin: boolean;
  saving: boolean;
  routeDst: string;
  setRouteDst: StringSetter;
  routeGw: string;
  setRouteGw: StringSetter;
  routeIface: string;
  setRouteIface: StringSetter;
  routeTable: string;
  setRouteTable: StringSetter;
  routeMetric: string;
  setRouteMetric: StringSetter;
  onAddRoute: () => void;
  onDeleteRoute: (idx: number) => void;
  gatewayLabel: (value?: string) => string;
};

export function StaticRoutesCard(props: StaticRoutesCardProps) {
  const {
    gateways,
    routes,
    isAdmin,
    saving,
    routeDst,
    setRouteDst,
    routeGw,
    setRouteGw,
    routeIface,
    setRouteIface,
    routeTable,
    setRouteTable,
    routeMetric,
    setRouteMetric,
    onAddRoute,
    onDeleteRoute,
    gatewayLabel,
  } = props;

  return (
    <Card padding="lg">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-[var(--text)]">Static routes</h2>
        {saving && <span className="text-xs text-[var(--text-muted)]">saving…</span>}
      </div>

      {isAdmin && (
        <details className="mt-3 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3">
          <summary className="cursor-pointer text-sm text-[var(--text)]">Add static route (advanced)</summary>
          <div className="mt-3 grid gap-2 md:grid-cols-2">
            <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
              Destination
              <InfoTip label="CIDR or default. Example: 0.0.0.0/0 or 10.0.0.0/24." />
              <input value={routeDst} onChange={(e) => setRouteDst(e.target.value)} placeholder="dst (CIDR or default)" className={INPUT_CLASS} />
            </label>
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
                Gateway
                <InfoTip label="Gateway IP or gateway name. Optional if iface is set." />
                <input
                  value={routeGw}
                  onChange={(e) => setRouteGw(e.target.value)}
                  placeholder="gateway (IP or gateway name, optional)"
                  className={INPUT_CLASS}
                />
              </label>
              {gateways.length > 0 && (
                <select
                  value=""
                  onChange={(e) => {
                    const v = e.target.value;
                    if (v) setRouteGw(v);
                  }}
                  className="w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                >
                  <option value="">Pick gateway…</option>
                  {gateways.map((g) => (
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
                className={INPUT_CLASS}
              />
            </label>
            <div className="grid grid-cols-2 gap-2">
              <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
                Table
                <InfoTip label="Routing table (0 = main)." />
                <input value={routeTable} onChange={(e) => setRouteTable(e.target.value)} placeholder="table (0=main)" className={INPUT_CLASS} />
              </label>
              <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
                Metric
                <InfoTip label="Optional route priority (lower wins)." />
                <input value={routeMetric} onChange={(e) => setRouteMetric(e.target.value)} placeholder="metric (optional)" className={INPUT_CLASS} />
              </label>
            </div>
            <div className="md:col-span-2 flex justify-end">
              <button
                onClick={onAddRoute}
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
            {routes.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-[var(--text-muted)]" colSpan={6}>
                  No static routes configured. Static routes direct traffic to specific subnets via a gateway.
                </td>
              </tr>
            )}
            {routes.map((r, idx) => (
              <tr key={`${r.dst}-${idx}`} className="table-row-hover transition-ui border-t border-amber-500/[0.1]">
                <td className="px-4 py-3 font-medium text-[var(--text)]">{r.dst}</td>
                <td className="px-4 py-3 text-[var(--text)]">{gatewayLabel(r.gateway)}</td>
                <td className="px-4 py-3 text-[var(--text)]">{r.iface ?? "\u2014"}</td>
                <td className="px-4 py-3 text-[var(--text)]">{r.table ?? 0}</td>
                <td className="px-4 py-3 text-[var(--text)]">{r.metric ?? "\u2014"}</td>
                <td className="px-4 py-3 text-right">
                  {isAdmin ? (
                    <button
                      onClick={() => onDeleteRoute(idx)}
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
  );
}

type PolicyRulesCardProps = {
  rules: PolicyRule[];
  isAdmin: boolean;
  saving: boolean;
  ruleSrc: string;
  setRuleSrc: StringSetter;
  ruleDst: string;
  setRuleDst: StringSetter;
  ruleTable: string;
  setRuleTable: StringSetter;
  rulePrio: string;
  setRulePrio: StringSetter;
  onAddRule: () => void;
  onDeleteRule: (idx: number) => void;
};

export function PolicyRulesCard(props: PolicyRulesCardProps) {
  const {
    rules,
    isAdmin,
    saving,
    ruleSrc,
    setRuleSrc,
    ruleDst,
    setRuleDst,
    ruleTable,
    setRuleTable,
    rulePrio,
    setRulePrio,
    onAddRule,
    onDeleteRule,
  } = props;

  return (
    <Card padding="lg">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-[var(--text)]">Policy-based routing (ip rules)</h2>
        {saving && <span className="text-xs text-[var(--text-muted)]">saving…</span>}
      </div>

      {isAdmin && (
        <details className="mt-3 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3">
          <summary className="cursor-pointer text-sm text-[var(--text)]">Add policy rule (advanced)</summary>
          <div className="mt-3 grid gap-2 md:grid-cols-2">
            <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
              Source CIDR
              <InfoTip label="Optional source match." />
              <input value={ruleSrc} onChange={(e) => setRuleSrc(e.target.value)} placeholder="src CIDR (optional)" className={INPUT_CLASS} />
            </label>
            <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
              Destination CIDR
              <InfoTip label="Optional destination match." />
              <input value={ruleDst} onChange={(e) => setRuleDst(e.target.value)} placeholder="dst CIDR (optional)" className={INPUT_CLASS} />
            </label>
            <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
              Table
              <InfoTip label="Routing table to use when rule matches (required)." />
              <input value={ruleTable} onChange={(e) => setRuleTable(e.target.value)} placeholder="table (required)" className={INPUT_CLASS} />
            </label>
            <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
              Priority
              <InfoTip label="Optional priority; lower wins." />
              <input value={rulePrio} onChange={(e) => setRulePrio(e.target.value)} placeholder="priority (optional)" className={INPUT_CLASS} />
            </label>
            <div className="md:col-span-2 flex justify-end">
              <button
                onClick={onAddRule}
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
            {rules.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-[var(--text-muted)]" colSpan={5}>
                  No policy rules configured.
                </td>
              </tr>
            )}
            {rules.map((r, idx) => (
              <tr key={`${r.table}-${idx}`} className="table-row-hover transition-ui border-t border-amber-500/[0.1]">
                <td className="px-4 py-3 text-[var(--text)]">{r.priority ?? "auto"}</td>
                <td className="px-4 py-3 text-[var(--text)]">{r.src ?? "\u2014"}</td>
                <td className="px-4 py-3 text-[var(--text)]">{r.dst ?? "\u2014"}</td>
                <td className="px-4 py-3 font-medium text-[var(--text)]">{r.table}</td>
                <td className="px-4 py-3 text-right">
                  {isAdmin ? (
                    <button
                      onClick={() => onDeleteRule(idx)}
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
  );
}
