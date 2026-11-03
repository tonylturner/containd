import type { ProtectionStatus, ProtectionSubsystem } from "./api-protection";

/** Keep shared protection detail in the banner while retaining health-only facts. */
export function hasTrafficProtectionNotice(status: ProtectionStatus | undefined): boolean {
  return !!status && !status.ready && (status.state !== "disabled"
    || status.subsystems.some(s => s.required && (s.fault || s.state === "failed")));
}

export function serviceRepairDirection(subsystems: ProtectionSubsystem[]): string {
  const repair = "Review the service configuration and referenced files, then commit corrected settings.";
  const blocked = subsystems.some(s => s.fault && !s.retryable && !s.nextRetryAt);
  return subsystems.some(s => s.retryable || s.nextRetryAt)
    ? `Automatic repair is underway. ${blocked ? repair : "Check service configuration and the appliance connection if this persists."}`
    : repair;
}

/** Copy uses effects, never guesses queue delivery from component errors. */
export function protectionView(status: ProtectionStatus | undefined): { title: string; action: string } {
  if (status?.ready) return { title: "Protecting", action: "" };
  if (!status || status.state === "unknown") return {
    title: "Protection unknown", action: "Protection status could not be checked. Check the appliance connection.",
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
  const action = status.subsystems.some(s => s.retryable || s.nextRetryAt) ? serviceRepairDirection(status.subsystems)
    : status.retryable ? "Check appliance health and traffic-inspection settings; retry is available."
    : status.state === "pending" ? "Wait for protection to finish, then check status."
    : status.state === "disabled" ? "Enable enforcement to protect traffic."
    : "Check appliance health and traffic-inspection settings before trying again.";
  switch (status.state) {
    case "pending": {
      const active = status.components.find((c) => c.required && c.state === "pending")
        ?? status.components.find((c) => c.state === "pending");
      const budget = active?.maxAttempts !== undefined && active.attempt !== undefined
        ? ` (retry ${active.attempt}/${active.maxAttempts})` : "";
      const owner = status.subsystems.find(s => s.required && !["ready", "off"].includes(s.state));
      const title = status.applyId === "" ? "Waiting for configuration"
        : owner ? `Configuration committed; ${owner.name} ${owner.name === "interfaces" ? "are" : "is"} ${owner.retryable ? "retrying" : "pending"}` : "Committed — protection pending";
      return { title: `${title}${budget}`, action: [effects, action].filter(Boolean).join(". ") };
    }
    case "failed":
      return { title: drops ? `Configured but not protecting — ${effects}`
        : uninspected ? `Inspection unavailable — ${effects}`
        : `Configured but not protecting${effects ? ` — ${effects}` : ""}`, action };
    case "degraded":
      if (!status.components.some(c => c.name.startsWith("nflog") && c.state !== "ready")) {
        return { title: "Protection needs attention", action: "Check appliance health and traffic-inspection settings." };
      }
      return { title: "Rule-hit logging unavailable", action: `Firewall rules are active, but rule-match logging is unavailable. ${action}` };
    case "disabled":
      return { title: "Protection disabled", action };
    case "protecting":
      return { title: "Protection could not be verified", action };
  }
}
