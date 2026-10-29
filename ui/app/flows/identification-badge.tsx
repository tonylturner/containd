import type { IdentificationAttributes } from "../../lib/api";
import { StatusBadge } from "../../components/StatusBadge";

/** Same status treatment as flow signals; identity is never a verdict. */
export function IdentificationBadge({ identification: id, application }: {
  identification?: Partial<IdentificationAttributes>;
  application?: string;
}) {
  const confirmed = id?.identification_state === "confirmed";
  const protocol = confirmed ? id.protocol : application;
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-1.5">
        {protocol ? (
          <StatusBadge variant="neutral">{protocol} · {confirmed ? "content" : "port"}</StatusBadge>
        ) : <span className="text-xs text-(--text-muted)">{id?.identification_state === "reject" ? "Not identified" : "Identification incomplete"}</span>}
        {id?.mismatch === true && <StatusBadge variant="warning">Mismatch</StatusBadge>}
      </div>
      {id?.outside_rule_port_scope === true && (
        <p className="text-xs text-(--amber)">Outside rule ports</p>
      )}
    </div>
  );
}
