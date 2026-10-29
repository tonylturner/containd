import type { PcapIdentification } from "../../lib/api";
import { IdentificationBadge } from "../flows/identification-badge";

export function IdentificationTable({ identifications }: { identifications: PcapIdentification[] }) {
  return (
    <section aria-labelledby="identifications-title" className="space-y-2">
      <h3 id="identifications-title" className="text-sm font-semibold text-(--text)">Content identifications ({identifications.length})</h3>
      <p className="text-xs text-(--text-muted)">Passive evidence only. Identification does not change verdicts; observation-bound connections do not generate rules.</p>
      {identifications.length === 0 ? <p className="text-sm text-(--text-muted)">No eligible connections identified.</p> : (
        <div className="overflow-x-auto rounded-xs border">
          <table className="w-full text-left text-sm">
            <thead className="bg-(--surface) text-xs uppercase tracking-wide text-(--text)">
              <tr>{["Connection", "Identified", "State / coverage", "Binding", "Expected endpoints", "Service", "Rule port scope"].map((label) => <th key={label} className="px-4 py-2">{label}</th>)}</tr>
            </thead>
            <tbody>
              {identifications.map(({ key, flowId, attributes: id }) => (
                <tr key={key} className="border-t table-row-hover transition-ui">
                  <td className="max-w-64 break-all px-4 py-2 font-mono text-xs text-(--text)" title={key}>{flowId}</td>
                  <td className="px-4 py-2"><IdentificationBadge identification={id} /></td>
                  <td className="px-4 py-2 text-xs text-(--text)">
                    <div>{id.identification_state}</div>
                    {id.identification_coverage && <div className="text-(--text-muted)">{id.identification_coverage}</div>}
                    <div className="text-(--text-muted)">{id.reason}</div>
                  </td>
                  <td className="px-4 py-2 text-xs text-(--text)">{id.binding}</td>
                  <td className="px-4 py-2 font-mono text-xs text-(--text)">{id.expected.map((p) => p || "none").join(" / ")}</td>
                  <td className="px-4 py-2 font-mono text-xs text-(--text)">{id.service_transport}/{id.service_port}</td>
                  <td className={`px-4 py-2 text-xs ${id.outside_rule_port_scope === true ? "text-(--amber)" : "text-(--text-muted)"}`}>
                    {id.outside_rule_port_scope === "unknown" ? "Unknown (no snapshot)" : id.outside_rule_port_scope ? "Outside rule ports" : "Not outside rule ports"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
