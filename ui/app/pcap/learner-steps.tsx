"use client";

import { secondaryButton } from "./suggestion-review";

export function LearnerSteps({
  hasDataset = true,
  generateReason,
  reviewReason,
  stageReason,
}: {
  hasDataset?: boolean;
  generateReason: string;
  reviewReason: string;
  stageReason: string;
}) {
  const steps = [
    { label: "1 Collect", target: "learner-collect", reason: "" },
    { label: "2 Generate", target: "learner-generate", reason: generateReason },
    { label: "3 Review", target: "learner-review", reason: reviewReason },
    { label: "4 Stage", target: "learner-stage", reason: stageReason },
  ];
  return (
    <nav aria-label="Learner steps" className="mb-4">
      <ol className="flex flex-wrap gap-3">
        {steps.map(({ label, target, reason }) => (
          <li key={target} className="min-w-0 max-w-64 flex-1 basis-40">
            <button
              className={secondaryButton}
              aria-controls={target}
              aria-describedby={`${target}-reason`}
              disabled={!hasDataset && target !== "learner-collect"}
              onClick={() => {
                const section = document.getElementById(target);
                section?.focus({ preventScroll: true });
                section?.scrollIntoView({ block: "start" });
              }}
            >
              {label}
            </button>
            <p id={`${target}-reason`} className="mt-1 text-xs text-(--text-muted)">
              {reason || "Ready to inspect. Actions remain explicit."}
            </p>
          </li>
        ))}
      </ol>
    </nav>
  );
}
