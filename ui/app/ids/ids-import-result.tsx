import { useMemo } from "react";
import type { IDSImportResult, IDSRule } from "../../lib/api";
import { isRuleEvaluable, RuleEvaluation } from "./ids-shared";

const ATTENTION_LIMIT = 20;

export function ImportResult({ result, onDismiss }: { result: IDSImportResult; onDismiss: () => void }) {
  const summary = useMemo(() => {
    let evaluable = 0;
    let storageOnly = 0;
    let withNotes = 0;
    let attentionCount = 0;
    const attention: IDSRule[] = [];
    for (const rule of result.rules) {
      const canEvaluate = isRuleEvaluable(rule);
      const hasNotes = (rule.conversionNotes?.length ?? 0) > 0;
      if (canEvaluate) evaluable++;
      else storageOnly++;
      if (hasNotes) withNotes++;
      if (!canEvaluate || hasNotes) {
        attentionCount++;
        if (attention.length < ATTENTION_LIMIT) attention.push(rule);
      }
    }
    return { evaluable, storageOnly, withNotes, attentionCount, attention };
  }, [result]);
  const more = summary.attentionCount - summary.attention.length;

  return (
    <section aria-label="Import result" className="mb-4 rounded-xs border bg-(--surface) p-4">
      <div className="flex items-start justify-between gap-3">
        <h2 className="text-sm font-medium">Import staged — commit to apply evaluable rules</h2>
        <button type="button" onClick={onDismiss} className="rounded-xs border px-3 py-1 text-sm">Dismiss</button>
      </div>
      <p className="mt-1 text-xs text-(--text-muted)">
        {result.imported.toLocaleString()} imported, {result.skipped.toLocaleString()} skipped.
        {" "}{summary.evaluable.toLocaleString()} evaluable, {summary.storageOnly.toLocaleString()} storage-only,
        {" "}{summary.withNotes.toLocaleString()} with conversion notes.
        {" "}Storage-only rules do not run, even when enabled.
      </p>
      {summary.attention.length > 0 && (
        <ul aria-label="Rules needing attention" className="mt-2 space-y-2">
          {summary.attention.map(rule => (
            <li key={rule.id}><span className="text-sm">{rule.id}</span><RuleEvaluation rule={rule} /></li>
          ))}
        </ul>
      )}
      {more > 0 && (
        <p className="mt-2 text-xs text-(--text-muted)">{more.toLocaleString()} more need attention — see the Rules table</p>
      )}
    </section>
  );
}
