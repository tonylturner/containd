import { StatusBadge } from "../../components/StatusBadge";
import { isRecord } from "../../lib/api-request";
import styles from "./firewall-rule-table.module.css";

export type DefaultAction = "ALLOW" | "DENY" | "unknown";

/** Only a readable firewall section can establish the implicit DENY default. */
export function effectiveDefaultAction(config: unknown): DefaultAction {
  if (!isRecord(config) || !isRecord(config.firewall)) return "unknown";
  const action: unknown = config.firewall.defaultAction;
  if (action === undefined || action === "" || action === "DENY") return "DENY";
  return action === "ALLOW" ? "ALLOW" : "unknown";
}

/** Informational fallback, never a configurable or movable rule. */
export function FirewallDefaultRow({ action }: { action: DefaultAction }) {
  return (
    <tr role="row" className={`${styles.ruleRow} border-t bg-(--surface2)`} aria-label="Default policy">
      <th role="rowheader" scope="row" className="px-3 py-3 text-left font-semibold">Default</th>
      <td role="cell" className="px-3 py-3 text-xs text-(--text-muted)">
        Applies when no enforcing rule allows, blocks or rejects traffic.
        {action === "ALLOW" && <div className="mt-1 text-amber">Unmatched traffic allowed</div>}
      </td>
      <td role="cell" data-label="Zones" className="whitespace-nowrap px-3 py-3">any → any</td>
      <td role="cell" data-label="Protocols" className="px-3 py-3">any</td>
      <td role="cell" data-label="Action" className="whitespace-nowrap px-3 py-3">
        <StatusBadge variant={action === "DENY" ? "error" : "warning"}>{action}</StatusBadge>
      </td>
      <td role="cell" data-label="Hits" className="px-3 py-3">—</td>
      <td role="cell" data-label="Actions" className="px-3 py-3 text-right text-xs text-(--text-muted)">Read-only</td>
    </tr>
  );
}
