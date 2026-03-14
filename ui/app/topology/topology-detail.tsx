"use client";

import type { TopoNodeData } from "./topology-shared";
import {
  nextActionsForNode,
  nodeOperatorHint,
  STATUS_COLORS,
} from "./topology-shared";
import s from "./topology.module.css";

export function DetailContent({ data }: { data: TopoNodeData }) {
  const sc = STATUS_COLORS[data.status || "ok"];
  const sl: Record<string, string> = {
    ok: "ONLINE",
    warn: "WARNING",
    crit: "CRITICAL",
    down: "OFFLINE",
  };
  const actions = nextActionsForNode(data);
  const hint = nodeOperatorHint(data);

  return (
    <>
      <div className={s.panelSection}>
        <div className={s.panelSectionLabel}>Status</div>
        <DRow k="State" v={sl[data.status || "ok"]} color={sc} />
        <DRow k="Type" v={data.nodeType.toUpperCase()} />
        {data.nodeType === "firewall" && (
          <>
            <DRow k="Hostname" v={data.hostname || ""} />
            <DRow k="Version" v={data.version || ""} cls={s.valAmber} />
            <DRow k="Uptime" v={data.uptime || ""} cls={s.valGreen} />
            <DRow k="CPU" v={`${data.cpu ?? 0}%`} />
            <DRow k="Memory" v={`${data.mem ?? 0}%`} />
            <DRow
              k="Sessions"
              v={String(data.sessions ?? 0)}
              cls={s.valCyan}
            />
          </>
        )}
        {data.nodeType === "zone" && (
          <>
            <DRow k="Subnet" v={data.subnet || ""} cls={s.valCyan} />
            <DRow k="Interface" v={data.iface || ""} />
            <DRow k="Hosts" v={String(data.hosts ?? 0)} />
            <DRow
              k="Active flows"
              v={String(data.flows ?? 0)}
              cls={s.valGreen}
            />
            {data.vlan ? (
              <DRow k="VLAN" v={String(data.vlan)} cls={s.valAmber} />
            ) : null}
            {data.desc ? <DRow k="Description" v={data.desc} /> : null}
          </>
        )}
        {data.nodeType === "gateway" && (
          <>
            <DRow k="IP" v={data.ip || ""} cls={s.valCyan} />
            <DRow k="ASN" v={data.asn || ""} />
            <DRow k="Latency" v={data.latency || ""} cls={s.valGreen} />
            <DRow k="Packet loss" v={data.loss || ""} cls={s.valGreen} />
          </>
        )}
        {hint ? <div className={s.panelHint}>{hint}</div> : null}
      </div>

      {actions.length > 0 && (
        <div className={s.panelSection}>
          <div className={s.panelSectionLabel}>Next Actions</div>
          <div className={s.actionList}>
            {actions.map((action) => (
              <a key={action.href} href={action.href} className={s.actionLink}>
                <span className={s.actionLabel}>{action.label}</span>
                <span className={s.actionMeta}>{action.detail}</span>
              </a>
            ))}
          </div>
        </div>
      )}

      {data.nodeType === "firewall" && data.interfaces && (
        <div className={s.panelSection}>
          <div className={s.panelSectionLabel}>Interfaces</div>
          <div className={s.ifaceList}>
            {data.interfaces.map((ifc) => (
              <div key={ifc.name} className={s.ifaceItem}>
                <div className={s.ifaceTop}>
                  <span className={s.ifaceName}>{ifc.name}</span>
                  <span
                    className={`${s.ifaceState} ${ifc.state === "up" ? s.ifaceUp : s.ifaceDown}`}
                  >
                    {ifc.state.toUpperCase()}
                  </span>
                </div>
                <div className={s.ifaceIp}>
                  {ifc.ip} &middot; {ifc.zone}
                </div>
                <div className={s.ifaceStats}>
                  <span>&darr; {ifc.rx}</span>
                  <span>&uarr; {ifc.tx}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {data.nodeType === "firewall" && data.routes && (
        <div className={s.panelSection}>
          <div className={s.panelSectionLabel}>Routing Table</div>
          <table className={s.routeTable}>
            <thead>
              <tr>
                <th>Destination</th>
                <th>Via</th>
                <th>Iface</th>
                <th>Origin</th>
              </tr>
            </thead>
            <tbody>
              {data.routes.map((r, i) => (
                <tr key={i}>
                  <td>{r.dst}</td>
                  <td>{r.gw}</td>
                  <td>{r.iface}</td>
                  <td>
                    <span
                      className={`${s.routeOrigin} ${r.origin === "static" ? s.originStatic : r.origin === "dynamic" ? s.originDynamic : s.originLocal}`}
                    >
                      {r.origin}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {data.rules && data.rules.length > 0 && (
        <div className={s.panelSection}>
          <div className={s.panelSectionLabel}>Policy Rules</div>
          <div className={s.ruleList}>
            {data.rules.map((r, i) => (
              <div
                key={i}
                className={`${s.ruleItem} ${r.action === "allow" ? s.ruleAllow : s.ruleDeny}`}
              >
                <span className={s.ruleAction}>{r.action.toUpperCase()}</span>
                <span className={s.ruleDesc}>{r.desc}</span>
                <span className={s.ruleHits}>{r.hits.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  );
}

function DRow({
  k,
  v,
  cls,
  color,
}: {
  k: string;
  v: string;
  cls?: string;
  color?: string;
}) {
  return (
    <div className={s.detailRow}>
      <span className={s.detailKey}>{k}</span>
      <span
        className={`${s.detailVal} ${cls || ""}`}
        style={color ? { color } : undefined}
      >
        {v}
      </span>
    </div>
  );
}
