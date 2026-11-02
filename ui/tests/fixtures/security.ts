import type { CheckEvidence, Conduit } from "../../lib/api";

const configured: CheckEvidence = { provenance: "configured", reason: "Derived from running firewall policy; not a runtime test." };
export const securityChecks: Conduit["checks"] = {
  defaultDeny: configured,
  protoWhitelist: configured,
  tlsEnforced: { provenance: "heuristic", reason: "Conventional encrypted-service ports do not verify encryption or enforce TLS." },
  ids: { provenance: "heuristic", reason: "Global IDS configuration does not establish conduit coverage." },
  mfaRequired: { provenance: "unknown", reason: "No conduit MFA evidence is available." },
  auditLogged: { provenance: "heuristic", reason: "A global syslog address does not prove conduit logging." },
  avEnabled: { provenance: "heuristic", reason: "Global AV configuration does not establish conduit scan coverage." },
};
