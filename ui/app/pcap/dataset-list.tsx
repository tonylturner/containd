import type { LearnDataset } from "../../lib/api-learn";
import { secondaryButton } from "./suggestion-review";
import { formatEvidenceTime } from "./evidence-time";

function facts(dataset: LearnDataset) {
  return {
    Dataset: dataset.id,
    Source: dataset.source,
    State: dataset.state,
    "Records / bytes": `${dataset.records} / ${dataset.bytes.toLocaleString()}`,
    Gaps: dataset.gaps?.length ? (
      <details>
        <summary className="cursor-pointer">Collection limitations: {dataset.gaps.length}</summary>
        {dataset.gaps.join(", ")}
      </details>
    ) : "None reported",
    Expires: formatEvidenceTime(dataset.expiresAt),
  };
}

export function DatasetList({
  datasets,
  selectedId,
  onOpen,
  onDelete,
  busy,
}: {
  datasets: LearnDataset[];
  selectedId?: string;
  onOpen: (dataset: LearnDataset) => void;
  onDelete?: (dataset: LearnDataset) => void;
  busy: boolean;
}) {
  function openButton(dataset: LearnDataset) {
    return (
      <div className="flex flex-wrap gap-2">
        <button
          className={`${secondaryButton} max-w-full break-all text-left`}
          aria-pressed={selectedId === dataset.id}
          onClick={() => onOpen(dataset)}
        >
          Open {dataset.id}
        </button>
        {onDelete && (
          <button
            className={`${secondaryButton} max-w-full break-all text-left`}
            disabled={busy || dataset.state !== "sealed"}
            title={dataset.state !== "sealed" ? "Only sealed datasets can be deleted. Stop collection first." : undefined}
            onClick={() => onDelete(dataset)}
          >
            Delete dataset {dataset.id}
          </button>
        )}
      </div>
    );
  }

  return (
    <div aria-label="Dataset list" className="min-w-0">
      <ul className="space-y-3 md:hidden">
        {datasets.map((dataset) => (
          <li key={dataset.id} className="min-w-0 space-y-3 border-t pt-3">
            <dl className="space-y-2 text-sm">
              {Object.entries(facts(dataset)).map(([label, value]) => (
                <div
                  key={label}
                  className="grid grid-cols-[6rem_minmax(0,1fr)] gap-3"
                >
                  <dt className="text-(--text-muted)">{label}</dt>
                  <dd className="min-w-0 break-all">{value}</dd>
                </div>
              ))}
            </dl>
            {openButton(dataset)}
          </li>
        ))}
      </ul>
      <div className="hidden overflow-x-auto rounded-xs border md:block">
        <table className="w-full text-left text-sm">
          <thead className="text-xs uppercase">
            <tr>
              {[
                "Dataset",
                "Source",
                "State",
                "Records / bytes",
                "Gaps",
                "Expires",
                "Review",
              ].map((label) => (
                <th key={label} className="px-3 py-2">
                  {label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {datasets.map((dataset) => (
              <tr key={dataset.id} className="border-t table-row-hover">
                {Object.entries(facts(dataset)).map(([label, value]) => (
                  <td
                    key={label}
                    className="max-w-60 break-words px-3 py-2 text-xs"
                  >
                    {value}
                  </td>
                ))}
                <td className="px-3 py-2">{openButton(dataset)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
