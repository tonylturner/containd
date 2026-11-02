import type { ICSPredicate } from "../../lib/api";
import { Disclosure } from "../../components/Disclosure";
import { protoMeta, summarizeGenericICS } from "./ics-shared";
import { summarizeIEC104 } from "./iec104";

export function ICSRuleDetails({ ics, filterProto }: { ics: ICSPredicate; filterProto: string }) {
  const constrained = Object.entries(ics).some(([key, value]) =>
    !["protocol", "mode"].includes(key) && !(["readOnly", "writeOnly"].includes(key) && value === false) && value != null &&
    (Array.isArray(value) ? value.length > 0 : value !== ""));
  return (
    <div className="mt-2 min-w-44 font-sans">
      <Disclosure title="Inspect rule" defaultOpen={constrained} indicator={constrained ? "Matching constraints" : undefined}>
        <div className="break-words font-mono">
          <strong className="block font-sans">{filterProto !== "all" ? protoMeta(filterProto).fcLabel : "Codes"}</strong>
          {ics.protocol === "iec104" ? summarizeIEC104(ics).types : summarizeGenericICS(ics)}
        </div>
        <div className="break-words font-mono">
          <strong className="block font-sans">{filterProto !== "all" ? protoMeta(filterProto).addrLabel : "Addresses"}</strong>
          {ics.protocol === "iec104" ? summarizeIEC104(ics).addresses : (ics.addresses ?? []).join(", ") || "*"}
        </div>
        <div><strong className="block">R/W</strong>{ics.readOnly ? "R" : ics.writeOnly ? "W" : "R/W"}</div>
      </Disclosure>
    </div>
  );
}
