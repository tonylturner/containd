export function ICSInlinePrerequisite({ configured, onSetup }: { configured?: boolean; onSetup?: () => void }) {
  if (configured) return null;
  return <p role="alert" className="mt-2 text-xs text-(--amber)">
    {configured === undefined ? "Inline inspection status unknown. " : "Enforce requires inline inspection; capture interfaces only observe. "}
    <a href="/firewall/#inline-inspection" onClick={onSetup} className="font-semibold underline">Set up inline inspection</a>
    {" "}before staging enforcing ICS rules. Monitor is non-blocking.
  </p>;
}
