import type { ConntrackEntry } from "../../lib/api";
import { TagList } from "../../components/TagList";

export function ConnectionInspection({ entry: e, id: detailId, open, reply }: {
  entry: ConntrackEntry;
  id: string;
  open: boolean;
  reply: string;
}) {
  return (
    <tr id={detailId} hidden={!open}>
      <td colSpan={7} className="border-t p-4">
        <dl className="grid gap-3 text-xs sm:grid-cols-3">
          <div><dt>Mark</dt><dd>{e.mark || "—"}</dd></div>
          <div><dt>Tags</dt><dd><TagList tags={e.tags} /></dd></div>
          <div><dt>Assured</dt><dd>{e.assured ? "yes" : "no"}</dd></div>
          <div><dt>TTL</dt><dd>{e.timeoutSecs ? `${e.timeoutSecs}s` : "—"}</dd></div>
          <div className="sm:col-span-2"><dt>Reply tuple (NAT)</dt><dd className="break-all">{reply}</dd></div>
        </dl>
      </td>
    </tr>
  );
}
