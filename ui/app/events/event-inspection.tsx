"use client";

import { useState } from "react";
import { api, type TelemetryEvent } from "../../lib/api";
import { describeICSEvidence } from "./iec104-evidence";

function eventSubtitle(ev: TelemetryEvent): string {
  const parts = [ev.kind];
  if (ev.proto && ev.proto !== "firewall") parts.push(ev.proto.toUpperCase());
  if (ev.transport) parts.push(ev.transport.toUpperCase());
  return parts.join(" · ");
}

function EventDetails({ id, onError }: { id: string; onError: (failed: boolean) => void }) {
  const [detail, setDetail] = useState<TelemetryEvent | null>(null);
  const [pending, setPending] = useState(false);
  async function load() {
    setPending(true);
    try {
      const event = await api.getEvent(id);
      setDetail(event);
      onError(!event);
    } finally {
      setPending(false);
    }
  }
  const json = detail ? JSON.stringify(detail, null, 2) : "";
  return (
    <div className="mt-2 text-xs">
      <button onClick={() => void load()} disabled={pending}
        className="rounded-xs border px-2 py-1 font-mono disabled:opacity-50">
        {pending ? "Loading" : "Event"} {id}
      </button>
      {detail && (
        <details open className="mt-2">
          <summary>Event JSON</summary>
          <a className="mt-1 inline-block underline" download={`event-${id}.json`}
            href={`data:application/json;charset=utf-8,${encodeURIComponent(json)}`}>Download event JSON</a>
          <pre className="mt-2 overflow-x-auto rounded-lg bg-black/40 p-3">{json}</pre>
        </details>
      )}
    </div>
  );
}

export function EventInspection({ event: ev, open, onError }: {
  event: TelemetryEvent;
  open: boolean;
  onError: (failed: boolean) => void;
}) {
  const evidence = describeICSEvidence(ev);
  return (
    <div id={`event-inspection-${ev.id}`} hidden={!open} className="min-w-0">
      <div className="mt-1 text-xs text-(--text-muted)">{eventSubtitle(ev)}</div>
      <EventDetails id={ev.id} onError={onError} />
      {evidence && (
        <details className="mt-2 rounded-xs border p-3 text-xs">
          <summary className="cursor-pointer">Message and session details</summary>
          <div className="mt-2 grid gap-x-4 gap-y-0.5 sm:grid-cols-2">
            {evidence.rows.map((row) => (
              <div key={row.label} className="flex gap-2">
                <span className="shrink-0 text-(--text-dim)">{row.label}</span>
                <span className="break-all font-mono text-[11px] text-(--text)">{row.value}</span>
              </div>
            ))}
          </div>
        </details>
      )}
      {ev.attributes && (
        <details className="mt-2 rounded-xs border p-3 text-xs">
          <summary className="cursor-pointer">Event attributes (JSON)</summary>
          <pre className="mt-2 overflow-x-auto rounded-lg bg-black/40 p-3 text-(--text)">
            {JSON.stringify(ev.attributes, null, 2)}
          </pre>
        </details>
      )}
    </div>
  );
}
