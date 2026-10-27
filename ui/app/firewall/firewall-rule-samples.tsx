"use client";

import { useState } from "react";

import type { RulePreview, TelemetryEvent } from "../../lib/api";
import { formatEndpoint } from "../../lib/endpoint";
import { formatTimestamp } from "../../lib/utils";
import { iec104TypeInfo } from "../ics/iec104";

function textAttr(attributes: Record<string, unknown>, key: string): string | undefined {
  const value = attributes[key];
  return typeof value === "string" && value !== "" ? value : undefined;
}

function codeAttr(attributes: Record<string, unknown>, key: string): number | undefined {
  const value = attributes[key];
  return typeof value === "number" && Number.isInteger(value) ? value : undefined;
}

/**
 * The ICS operation an event decoded: a function code (Modbus, DNP3, S7comm,
 * CIP), a service (BACnet, CIP, OPC UA, MMS) or an IEC 104 Type ID; null
 * for an event without one.
 */
function icsOperation(ev: TelemetryEvent): string | null {
  const a = ev.attributes;
  if (!a) return null;
  const fc = codeAttr(a, "function_code");
  const fcName = textAttr(a, "function_name");
  if (fc !== undefined) return fcName ? `function ${fc} ${fcName}` : `function ${fc}`;
  const service = textAttr(a, "service_name") ?? textAttr(a, "service");
  const serviceCode = codeAttr(a, "service_code");
  if (service || serviceCode !== undefined) {
    return ["service", serviceCode, service].filter((part) => part !== undefined).join(" ");
  }
  const typeId = codeAttr(a, "type_id");
  if (typeId !== undefined) return `type ${typeId} ${iec104TypeInfo(typeId).name}`;
  return null;
}

function SampleRow({ ev }: { ev: TelemetryEvent }) {
  const operation = icsOperation(ev);
  return (
    <li className="grid gap-x-3 gap-y-0.5 px-3 py-1.5 text-xs md:grid-cols-[11rem_9rem_1fr]">
      <time dateTime={ev.timestamp} className="text-(--text-muted)">{formatTimestamp(ev.timestamp)}</time>
      <span className="wrap-break-word text-(--text)">
        {ev.proto || ev.transport || "event"} / {ev.kind}
        {operation && <span className="block text-(--text-muted)">{operation}</span>}
      </span>
      <span className="wrap-break-word font-mono text-[11px] text-(--text)">
        {formatEndpoint(ev.srcIp, ev.srcPort)} → {formatEndpoint(ev.dstIp, ev.dstPort)}
        {ev.transport && <span className="text-(--text-muted)"> ({ev.transport})</span>}
      </span>
    </li>
  );
}

/**
 * The window of events a rule impact preview searched and the newest
 * matching events it returned, collapsed until asked for.
 */
export function RulePreviewEvents({ preview }: { preview: RulePreview }) {
  const [open, setOpen] = useState(false);
  const samples = preview.sample_matches;
  const range = preview.time_range;
  return (
    <>
      {range && (
        <p className="mt-1 text-xs text-(--text-muted)">
          Events searched: <time dateTime={range.start}>{formatTimestamp(range.start)}</time>
          {" to "}
          <time dateTime={range.end}>{formatTimestamp(range.end)}</time>
        </p>
      )}
      {samples.length > 0 && (
        <details
          onToggle={(event) => setOpen(event.currentTarget.open)}
          className="mt-2 rounded-xs border bg-(--surface)"
        >
          <summary className="cursor-pointer px-3 py-2 text-xs text-(--text) focus-visible:outline-solid">
            {open ? "Hide" : "Show"} {samples.length} sample {samples.length === 1 ? "event" : "events"}
            {samples.length < preview.match_count && (
              <span className="ml-1 text-(--text-muted)">(the newest of {preview.match_count} matches)</span>
            )}
          </summary>
          <ul aria-label="Sample matching events" className="max-h-60 divide-y overflow-y-auto border-t">
            {samples.map((ev) => <SampleRow key={ev.id} ev={ev} />)}
          </ul>
        </details>
      )}
    </>
  );
}
