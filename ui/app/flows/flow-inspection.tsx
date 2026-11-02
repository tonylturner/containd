import type { FlowSummary } from "../../lib/api";
import { TagList } from "../../components/TagList";

export function FlowInspection({ flow: f, open }: { flow: FlowSummary; open: boolean }) {
  return (
    <tr id={`flow-detail-${f.session_id ?? f.flowId}`} hidden={!open}>
      <td colSpan={5} className="border-t p-4">
        <dl className="grid gap-3 text-xs sm:grid-cols-3">
          <div><dt>Flow</dt><dd className="break-all font-mono">{f.flowId}{f.session_id && <span className="block">{f.session_id}</span>}</dd></div>
          <div><dt>Tags</dt><dd><TagList tags={f.tags} /></dd></div>
          <div><dt>First Seen</dt><dd>{new Date(f.firstSeen).toLocaleString()}</dd></div>
        </dl>
      </td>
    </tr>
  );
}
