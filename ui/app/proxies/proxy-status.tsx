import { TechnicalDetails } from "../../components/TechnicalDetails";
import { ServiceStatusStrip } from "../system/services/service-presentation";

function faultSummary(diagnostic: string) {
  if (/preflight/i.test(diagnostic)) return "Generated proxy configuration failed validation; review Technical details.";
  if (/certificate is not currently valid/i.test(diagnostic)) return "Proxy TLS certificate is expired or not yet valid; provision a currently valid certificate.";
  if (/read matching certificate\/key pair/i.test(diagnostic)) return "Proxy TLS certificate/key pair could not be read or does not match.";
  if (/certificate material escapes/i.test(diagnostic)) return "Proxy TLS certificate material resolves outside the certificate directory.";
  if (/certificate|certRef|site .+ TLS/i.test(diagnostic)) return "Proxy certificate configuration failed; check the reference and provisioned certificate/key pair.";
  // Keep an unexpected cause visible, without allowing a multiline daemon dump
  // to dominate the status strip. Exact output remains available below.
  const firstLine = diagnostic.trim().split(/\r?\n/, 1)[0] || "Proxy reported a fault; review Technical details.";
  return firstLine.length > 200 ? `${firstLine.slice(0, 200)}…` : firstLine;
}

export function ProxyStatus({ label, configured, running, updated, available, diagnostic, faulted }: {
  label: string;
  configured?: boolean;
  running?: boolean;
  updated?: string;
  available: boolean;
  diagnostic?: string;
  faulted?: boolean;
}) {
  return (
    <div className="min-w-0 [&_span]:min-w-0">
      <ServiceStatusStrip label={label} configured={configured} running={running} updated={updated}
        attention={!available ? "Live proxy status unavailable — use Refresh to retry"
          : diagnostic ? faultSummary(diagnostic) : faulted ? "Service faulted" : undefined}
        summary={diagnostic ? <TechnicalDetails>
          <p className="font-medium">Proxy diagnostic output (including generated configuration when reported)</p>
          <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all">{diagnostic}</pre>
        </TechnicalDetails> : undefined} />
    </div>
  );
}
