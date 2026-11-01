/**
 * A boot fault from the management reservation view: the stored running
 * configuration was refused at boot, and the engine runs the minimal
 * default-deny recovery ruleset instead. It holds with or without a
 * reservation, and needs an operator.
 */
export function BootFaultStatus({
  bootFault,
  recovery,
  reserved,
  className = "",
}: {
  bootFault: string;
  recovery?: string;
  /** A reservation keeps its management path; otherwise the stored listener access stays. */
  reserved: boolean;
  className?: string;
}) {
  return (
    <div role="status" className={`rounded-xs border border-amber/30 bg-amber/10 px-3 py-2 text-amber ${className}`}>
      <p className="font-semibold">Configuration apply paused</p>
      <p>{recovery || "recovery pending: ruleset not verified"}</p>
      <details className="wrap-break-word">
        <summary className="cursor-pointer">Configuration fault details</summary>
        {bootFault}
      </details>
      <p>
        {reserved
          ? "Reserved management remains available."
          : "The recovery ruleset keeps the stored management listener access."}{" "}
        Commit a safe configuration, roll back to a safe snapshot, or factory reset to resume applying configuration. The saved configuration has not been activated after startup.
      </p>
    </div>
  );
}
