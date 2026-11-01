import { StatusBadge } from "../../components/StatusBadge";
import { isRecord } from "../../lib/api-request";

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
    <tr className="border-t bg-(--surface2)" aria-label="Default policy">
      <th scope="row" className="px-3 py-3 text-left font-semibold">Default</th>
      <td className="px-3 py-3 text-xs text-(--text-muted)">—</td>
      <td className="px-3 py-3 text-xs text-(--text-muted)">
        Applies when no enforcing rule allows, blocks or rejects traffic.
      </td>
      <td className="whitespace-nowrap px-3 py-3">any → any</td>
      <td className="px-3 py-3">any</td>
      <td className="px-3 py-3">—</td>
      <td className="px-3 py-3">—</td>
      <td className="px-3 py-3">
        <div className="space-y-1">
          <StatusBadge variant={action === "DENY" ? "error" : "warning"}>{action}</StatusBadge>
          {action === "ALLOW" && <StatusBadge variant="warning">Unmatched traffic allowed</StatusBadge>}
        </div>
      </td>
      <td className="px-3 py-3">—</td>
      <td className="px-3 py-3">—</td>
      <td className="px-3 py-3">—</td>
      <td className="px-3 py-3 text-right text-xs text-(--text-muted)">Read-only</td>
    </tr>
  );
}
