import type { ReactNode } from "react";

/** Keep exact diagnostics available without leading with implementation terms. */
export function TechnicalDetails({ children, summary = "Technical details" }: {
  children: ReactNode;
  summary?: string;
}) {
  return (
    <details className="mt-2 text-xs">
      <summary className="cursor-pointer">{summary}</summary>
      <div className="mt-1 space-y-1 break-words whitespace-pre-wrap">{children}</div>
    </details>
  );
}
