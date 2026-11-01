import type { ProtectionStatus } from "./api-protection";

/** Copy uses effects, never guesses queue delivery from component errors. */
export function protectionView(status: ProtectionStatus | undefined): { title: string; action: string } {
  if (!status || status.state === "unknown") return {
    title: "Protection unknown", action: "Protection status could not be read. Check engine connectivity.",
  };
  const affected = (effect: string) => status.effects.filter((e) => e.effect === effect).map((e) => e.traffic).join(", ");
  const drops = affected("fail_closed_drop");
  const uninspected = affected("not_inspected");
  const uncertain = affected("unknown");
  const effects = [
    drops && `${drops} is dropping (fail closed)`,
    uninspected && `${uninspected} is not being inspected by containd`,
    uncertain && `${uncertain}: traffic protection is unknown`,
  ].filter(Boolean).join("; ");
  const action = status.retryable ? "Retry protection, then check status."
    : status.state === "pending" ? "Wait for protection to finish, then check status."
    : status.state === "disabled" ? "Enable enforcement to protect traffic."
    : "Check engine and capture configuration before applying again.";
  switch (status.state) {
    case "pending": {
      const active = status.components.find((c) => c.required && c.state === "pending")
        ?? status.components.find((c) => c.state === "pending");
      const budget = active?.maxAttempts !== undefined && active.attempt !== undefined
        ? ` (retry ${active.attempt}/${active.maxAttempts})` : "";
      return { title: `Committed — protection pending${budget}`, action: [effects, action].filter(Boolean).join(". ") };
    }
    case "failed":
      return { title: drops ? `Configured but not protecting — ${effects}`
        : uninspected ? `Inspection unavailable — ${effects}`
        : `Configured but not protecting${effects ? ` — ${effects}` : ""}`, action };
    case "degraded":
      return { title: "Rule-hit logging unavailable", action: `Nft policy is enforcing; rule-hit evidence is unavailable. ${action}` };
    case "disabled":
      return { title: "Protection disabled", action };
    case "protecting":
      return { title: "Protecting", action: "" };
  }
}
