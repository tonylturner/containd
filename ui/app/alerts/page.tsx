"use client";

import { useEffect, useMemo, useState } from "react";

import { api, type TelemetryEvent } from "../../lib/api";
import { Shell } from "../../components/Shell";
import { StatusBadge } from "../../components/StatusBadge";
import { EmptyState } from "../../components/EmptyState";
import { Pagination } from "../../components/TableControls";

const PAGE_SIZES = [10, 25, 50, 100];

const severityVariant = (sev: string) => {
  switch (sev) {
    case "critical": return "error" as const;
    case "high": return "warning" as const;
    case "medium": return "info" as const;
    default: return "neutral" as const;
  }
};

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export default function AlertsPage() {
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [live, setLive] = useState(true);
  const [selected, setSelected] = useState<TelemetryEvent | null>(null);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(25);
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState("");

  async function refresh() {
    setError(null);
    const list = await api.listEvents(2000);
    if (!list) { setError("Failed to load alerts."); return; }
    setEvents(list);
  }

  useEffect(() => {
    refresh();
    if (!live) return;
    const id = setInterval(refresh, 10000);
    return () => clearInterval(id);
  }, [live]);

  const alerts = useMemo(() => {
    let list = events.filter((e) => e.proto === "ids" && e.kind === "alert");
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter((ev) => {
        const msg = String(ev.attributes?.["message"] ?? "");
        const ruleId = String(ev.attributes?.["rule_id"] ?? "");
        const sev = String(ev.attributes?.["severity"] ?? "");
        return msg.toLowerCase().includes(q) || ruleId.toLowerCase().includes(q) ||
          sev.toLowerCase().includes(q) || (ev.srcIp ?? "").includes(q) || (ev.dstIp ?? "").includes(q);
      });
    }
    if (sevFilter) {
      list = list.filter((ev) => String(ev.attributes?.["severity"] ?? "low") === sevFilter);
    }
    return list;
  }, [events, search, sevFilter]);

  const totalPages = Math.max(1, Math.ceil(alerts.length / pageSize));
  const clampedPage = Math.min(page, totalPages - 1);
  const pageData = alerts.slice(clampedPage * pageSize, (clampedPage + 1) * pageSize);

  useEffect(() => { setPage(0); }, [search, sevFilter, pageSize]);

  // Severity summary
  const sevCounts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const ev of alerts) {
      const s = String(ev.attributes?.["severity"] ?? "low") as keyof typeof c;
      if (s in c) c[s]++;
    }
    return c;
  }, [alerts]);

  return (
    <Shell
      title="IDS Alerts"
      actions={
        <div className="flex items-center gap-3">
          <button onClick={() => setLive((v) => !v)}
            className={`inline-flex items-center gap-1.5 rounded-sm border px-3 py-1.5 text-xs font-medium transition-colors ${
              live ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20"
                : "border-amber-500/[0.15] bg-[var(--surface2)] text-[var(--text-muted)] hover:bg-amber-500/[0.1]"
            }`}>
            {live && (
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
              </span>
            )}
            {live ? "Live" : "Paused"}
          </button>
          <button onClick={refresh}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-xs font-medium text-[var(--text)] transition-colors hover:bg-amber-500/[0.1]">
            Refresh
          </button>
        </div>
      }
    >
      {error && <div className="mb-4 rounded-sm border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">{error}</div>}

      {/* Severity summary */}
      <div className="mb-4 flex gap-3">
        {(["critical", "high", "medium", "low"] as const).map((s) => (
          <button key={s} onClick={() => setSevFilter(sevFilter === s ? "" : s)}
            className={`flex items-center gap-1.5 rounded-sm border px-3 py-1.5 text-xs tabular-nums transition-ui ${
              sevFilter === s ? "border-amber-500/30 bg-amber-500/[0.08] text-amber-400"
                : "border-amber-500/[0.08] bg-[var(--surface)] text-[var(--text-muted)] hover:text-[var(--text)]"
            }`}>
            <span className={`inline-block h-2 w-2 rounded-full ${
              s === "critical" ? "bg-red-500" : s === "high" ? "bg-orange-500" : s === "medium" ? "bg-amber-500" : "bg-emerald-500"
            }`} />
            {s} <span className="font-mono">{sevCounts[s]}</span>
          </button>
        ))}
      </div>

      {/* Search */}
      <div className="mb-3 max-w-lg">
        <div className="relative">
          <svg className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--text-dim)]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
          </svg>
          <input value={search} onChange={(e) => setSearch(e.target.value)}
            placeholder="Search alerts by message, rule ID, IP..."
            className="input-industrial w-full py-1.5 pl-9 pr-3 text-sm" />
        </div>
      </div>

      {alerts.length === 0 ? (
        <EmptyState title="No IDS alerts"
          description={events.some((e) => e.proto === "ids") ? "No alerts match your filters." : "No alerts yet. Alerts appear when the IDS engine detects suspicious activity."} />
      ) : (
        <div className="flex gap-4">
          {/* Alert list */}
          <div className={`${selected ? "w-1/2" : "w-full"} transition-all`}>
            <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] overflow-hidden">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="bg-[var(--surface)] text-[9px] font-medium uppercase tracking-[2px] text-[var(--text-dim)]">
                    <th className="px-4 py-2.5">Message</th>
                    <th className="px-4 py-2.5">Severity</th>
                    <th className="px-4 py-2.5">Source</th>
                    <th className="px-4 py-2.5">Dest</th>
                    <th className="px-4 py-2.5">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {pageData.map((ev) => {
                    const sev = String(ev.attributes?.["severity"] ?? "low");
                    const msg = String(ev.attributes?.["message"] ?? ev.attributes?.["rule_id"] ?? "IDS alert");
                    const isActive = selected?.id === ev.id;
                    return (
                      <tr key={ev.id}
                        onClick={() => setSelected(isActive ? null : ev)}
                        className={`table-row-hover transition-ui border-t border-amber-500/[0.1] cursor-pointer ${isActive ? "bg-amber-500/[0.06]" : ""}`}>
                        <td className="px-4 py-2.5 font-medium text-[var(--text)] max-w-[200px] truncate" title={msg}>{msg}</td>
                        <td className="px-4 py-2.5"><StatusBadge variant={severityVariant(sev)} dot>{sev}</StatusBadge></td>
                        <td className="px-4 py-2.5 text-xs text-[var(--text)] font-mono">{ev.srcIp}:{ev.srcPort}</td>
                        <td className="px-4 py-2.5 text-xs text-[var(--text)] font-mono">{ev.dstIp}:{ev.dstPort}</td>
                        <td className="whitespace-nowrap px-4 py-2.5 text-xs text-[var(--text-muted)]">{new Date(ev.timestamp).toLocaleString()}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              <Pagination page={clampedPage} totalPages={totalPages} totalItems={alerts.length}
                onPage={setPage} pageSize={pageSize} onPageSize={(s) => { setPageSize(s); setPage(0); }} pageSizeOptions={PAGE_SIZES} />
            </div>
          </div>

          {/* Detail panel */}
          {selected && (
            <div className="w-1/2 shrink-0">
              <AlertDetailPanel event={selected} onClose={() => setSelected(null)} />
            </div>
          )}
        </div>
      )}
    </Shell>
  );
}

/* ── Alert Detail Panel ── */

// Modbus function code names
const MODBUS_FC: Record<number, string> = {
  1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers",
  4: "Read Input Registers", 5: "Force Single Coil", 6: "Preset Single Register",
  7: "Read Exception Status", 8: "Diagnostics", 11: "Get Comm Event Counter",
  12: "Get Comm Event Log", 15: "Write Multiple Coils", 16: "Write Multiple Registers",
  17: "Report Server ID", 20: "Read File Record", 21: "Write File Record",
  22: "Mask Write Register", 23: "Read/Write Multiple Registers", 24: "Read FIFO Queue",
  43: "Encapsulated Interface Transport",
};

function formatHexDump(hexStr: string): { offset: string; hex: string; ascii: string }[] {
  const bytes = hexStr.match(/.{1,2}/g) ?? [];
  const rows: { offset: string; hex: string; ascii: string }[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const offset = i.toString(16).padStart(4, "0");
    const hex = chunk.map((b) => b).join(" ").padEnd(47, " ");
    const ascii = chunk
      .map((b) => { const c = parseInt(b, 16); return c >= 32 && c < 127 ? String.fromCharCode(c) : "."; })
      .join("");
    rows.push({ offset, hex, ascii });
  }
  return rows;
}

function AlertDetailPanel({ event, onClose }: { event: TelemetryEvent; onClose: () => void }) {
  const attrs = event.attributes ?? {};
  const sev = String(attrs["severity"] ?? "low");
  const msg = String(attrs["message"] ?? "IDS alert");
  const ruleId = String(attrs["rule_id"] ?? "");
  const desc = attrs["description"] as string | undefined;
  const eventProto = String(attrs["event_proto"] ?? "");
  const eventKind = String(attrs["event_kind"] ?? "");
  const sourceFormat = attrs["source_format"] as string | undefined;
  const refs = (attrs["references"] as string[] | undefined) ?? [];
  const cves = (attrs["cve"] as string[] | undefined) ?? [];
  const mitreIds = (attrs["mitre_attack_ids"] as string[] | undefined) ?? [];
  const matchedPatterns = (attrs["matched_patterns"] as string[] | undefined) ?? [];
  const eventAttrs = (attrs["event_attrs"] as Record<string, unknown> | undefined) ?? {};
  const labels = (attrs["labels"] as Record<string, string> | undefined) ?? {};

  const isModbus = eventProto === "modbus";
  const isTLS = eventProto === "tls";
  const isDNP3 = eventProto === "dnp3";
  const isS7 = eventProto === "s7comm";
  const isCIP = eventProto === "enip" || eventProto === "cip";
  const isBACnet = eventProto === "bacnet";

  return (
    <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] overflow-hidden flex flex-col h-[calc(100vh-240px)] sticky top-4">
      {/* Header */}
      <div className="flex items-start justify-between gap-2 border-b border-amber-500/[0.1] px-4 py-3">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-[var(--text)] break-words">{msg}</h3>
          <div className="mt-1 flex items-center gap-2 flex-wrap">
            <StatusBadge variant={severityVariant(sev)} dot>{sev}</StatusBadge>
            {eventProto && (
              <span className="rounded-sm border border-blue-500/20 bg-blue-500/10 px-1.5 py-0.5 text-[10px] font-medium text-blue-400 uppercase">{eventProto}</span>
            )}
            {sourceFormat && <span className="text-[10px] text-[var(--text-muted)] uppercase">{sourceFormat}</span>}
          </div>
        </div>
        <button onClick={onClose} className="shrink-0 rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-0.5 text-xs text-[var(--text-muted)] transition-ui hover:bg-amber-500/[0.08]">
          Close
        </button>
      </div>

      <div className="flex-1 overflow-y-auto">
        {/* Rule info */}
        <DetailSection label="Rule">
          <DetailRow label="Rule ID" value={ruleId} mono />
          {desc && <DetailRow label="Description" value={desc} />}
          <DetailRow label="Triggered by" value={`${eventProto} / ${eventKind}`} />
          <DetailRow label="Time" value={new Date(event.timestamp).toLocaleString()} />
        </DetailSection>

        {/* Network */}
        <DetailSection label="Network">
          <DetailRow label="Source" value={`${event.srcIp}:${event.srcPort}`} mono />
          <DetailRow label="Destination" value={`${event.dstIp}:${event.dstPort}`} mono />
          {event.transport && <DetailRow label="Transport" value={event.transport.toUpperCase()} />}
          {event.flowId && <DetailRow label="Flow ID" value={event.flowId} mono />}
        </DetailSection>

        {/* ── Protocol Analysis (Modbus) ── */}
        {isModbus && Object.keys(eventAttrs).length > 0 && (
          <DetailSection label="Modbus Protocol Analysis">
            {eventAttrs["function_code"] != null && (() => {
              const fc = Number(eventAttrs["function_code"]);
              const fcName = MODBUS_FC[fc] ?? `Unknown (${fc})`;
              const isWrite = eventAttrs["is_write"] === true;
              return (
                <>
                  <div className="flex justify-between gap-3 text-xs">
                    <span className="text-[var(--text-dim)] shrink-0">Function Code</span>
                    <span className="text-right font-mono text-[11px]">
                      <span className={isWrite ? "text-red-400" : "text-emerald-400"}>FC {fc}</span>
                      <span className="text-[var(--text-muted)] ml-2">{fcName}</span>
                    </span>
                  </div>
                  <div className="flex justify-between gap-3 text-xs">
                    <span className="text-[var(--text-dim)]">Operation</span>
                    <span className={`text-right font-mono text-[11px] font-medium ${isWrite ? "text-red-400" : "text-emerald-400"}`}>
                      {isWrite ? "WRITE" : "READ"}
                    </span>
                  </div>
                </>
              );
            })()}
            {eventAttrs["unit_id"] != null && (
              <DetailRow label="Unit ID" value={String(eventAttrs["unit_id"])} mono />
            )}
            {eventAttrs["transaction_id"] != null && (
              <DetailRow label="Transaction ID" value={String(eventAttrs["transaction_id"])} mono />
            )}
            {eventAttrs["address"] != null && (
              <DetailRow label="Start Address" value={`${eventAttrs["address"]} (0x${Number(eventAttrs["address"]).toString(16).padStart(4, "0")})`} mono />
            )}
            {eventAttrs["quantity"] != null && (
              <DetailRow label="Quantity" value={`${eventAttrs["quantity"]} registers/coils`} mono />
            )}
            {eventAttrs["address"] != null && eventAttrs["quantity"] != null && (
              <DetailRow label="Address Range" value={`${eventAttrs["address"]}–${Number(eventAttrs["address"]) + Number(eventAttrs["quantity"]) - 1}`} mono />
            )}
            {eventAttrs["exception_code"] != null && (
              <div className="rounded-sm border border-red-500/20 bg-red-500/[0.06] px-3 py-2 mt-1">
                <div className="flex justify-between text-xs">
                  <span className="text-red-400 font-medium">Exception</span>
                  <span className="font-mono text-[11px] text-red-300">
                    Code {String(eventAttrs["exception_code"])} — {String(eventAttrs["exception_description"] ?? "unknown")}
                  </span>
                </div>
              </div>
            )}
            {eventAttrs["sub_function"] != null && (
              <DetailRow label="Sub-function" value={`${eventAttrs["sub_function"]} (${eventAttrs["sub_function_name"] ?? "unknown"})`} mono />
            )}
          </DetailSection>
        )}

        {/* ── Protocol Analysis (TLS) ── */}
        {isTLS && Object.keys(eventAttrs).length > 0 && (
          <DetailSection label="TLS / Certificate Analysis">
            {eventAttrs["sni"] != null && (
              <DetailRow label="Server Name (SNI)" value={String(eventAttrs["sni"])} mono />
            )}
            {eventAttrs["tls_version"] != null && (
              <DetailRow label="TLS Version" value={String(eventAttrs["tls_version"])} mono />
            )}
            {eventAttrs["cipher_suite"] != null && (
              <DetailRow label="Cipher Suite" value={String(eventAttrs["cipher_suite"])} mono />
            )}
            {eventAttrs["ja3_hash"] != null && (
              <DetailRow label="JA3 Fingerprint" value={String(eventAttrs["ja3_hash"])} mono />
            )}
            {(eventAttrs["expected_cn"] != null || eventAttrs["observed_cn"] != null) && (
              <div className="rounded-sm border border-red-500/20 bg-red-500/[0.06] px-3 py-2 mt-1 space-y-1.5">
                <div className="text-[10px] font-medium uppercase tracking-wider text-red-400">Certificate Mismatch</div>
                {eventAttrs["expected_cn"] != null && (
                  <div className="flex justify-between gap-3 text-xs">
                    <span className="text-emerald-400/70">Expected CN</span>
                    <span className="font-mono text-[11px] text-emerald-300">{String(eventAttrs["expected_cn"])}</span>
                  </div>
                )}
                {eventAttrs["observed_cn"] != null && (
                  <div className="flex justify-between gap-3 text-xs">
                    <span className="text-red-400/70">Observed CN</span>
                    <span className="font-mono text-[11px] text-red-300">{String(eventAttrs["observed_cn"])}</span>
                  </div>
                )}
              </div>
            )}
            {eventAttrs["issuer"] != null && (
              <DetailRow label="Issuer" value={String(eventAttrs["issuer"])} mono />
            )}
            {eventAttrs["serial_number"] != null && (
              <DetailRow label="Serial Number" value={String(eventAttrs["serial_number"])} mono />
            )}
            {eventAttrs["fingerprint"] != null && (
              <DetailRow label="Cert Fingerprint" value={String(eventAttrs["fingerprint"])} mono />
            )}
            {(eventAttrs["not_before"] != null || eventAttrs["not_after"] != null) && (
              <div className="flex gap-4 text-xs">
                {eventAttrs["not_before"] != null && (
                  <div>
                    <span className="text-[var(--text-dim)]">Valid from </span>
                    <span className="font-mono text-[11px] text-[var(--text)]">{String(eventAttrs["not_before"]).slice(0, 10)}</span>
                  </div>
                )}
                {eventAttrs["not_after"] != null && (
                  <div>
                    <span className="text-[var(--text-dim)]">to </span>
                    <span className="font-mono text-[11px] text-[var(--text)]">{String(eventAttrs["not_after"]).slice(0, 10)}</span>
                  </div>
                )}
              </div>
            )}
          </DetailSection>
        )}

        {/* ── Protocol Analysis (DNP3) ── */}
        {isDNP3 && Object.keys(eventAttrs).length > 0 && (
          <DetailSection label="DNP3 Protocol Analysis">
            {eventAttrs["function_code"] != null && (
              <DetailRow label="Function Code" value={`${eventAttrs["function_code"]} (${eventAttrs["function_name"] ?? ""})`} mono />
            )}
            {eventAttrs["iin_flags"] != null && (
              <DetailRow label="IIN Flags" value={String(eventAttrs["iin_flags"])} mono />
            )}
            {eventAttrs["object_groups"] != null && (
              <DetailRow label="Object Groups" value={String(eventAttrs["object_groups"])} mono />
            )}
            {eventAttrs["object_count"] != null && (
              <DetailRow label="Object Count" value={String(eventAttrs["object_count"])} mono />
            )}
          </DetailSection>
        )}

        {/* ── Protocol Analysis (S7comm) ── */}
        {isS7 && Object.keys(eventAttrs).length > 0 && (
          <DetailSection label="S7comm Protocol Analysis">
            {eventAttrs["function_code"] != null && (
              <DetailRow label="Function" value={`${eventAttrs["function_name"] ?? eventAttrs["function_code"]}`} mono />
            )}
            {eventAttrs["area"] != null && (
              <DetailRow label="Memory Area" value={String(eventAttrs["area"])} mono />
            )}
            {eventAttrs["address"] != null && (
              <DetailRow label="Address" value={String(eventAttrs["address"])} mono />
            )}
            {eventAttrs["db_number"] != null && (
              <DetailRow label="DB Number" value={String(eventAttrs["db_number"])} mono />
            )}
            {eventAttrs["item_count"] != null && (
              <DetailRow label="Item Count" value={String(eventAttrs["item_count"])} mono />
            )}
            {eventAttrs["is_write"] === true && (
              <div className="text-xs font-medium text-red-400">WRITE OPERATION</div>
            )}
            {eventAttrs["is_control"] === true && (
              <div className="text-xs font-medium text-orange-400">CONTROL OPERATION (CPU Start/Stop)</div>
            )}
            {eventAttrs["safety_critical"] === true && (
              <div className="rounded-sm border border-red-500/20 bg-red-500/10 px-2 py-1 text-xs text-red-400 font-medium">
                SAFETY-CRITICAL DB ACCESS
              </div>
            )}
          </DetailSection>
        )}

        {/* ── Protocol Analysis (CIP/EtherNet/IP) ── */}
        {isCIP && Object.keys(eventAttrs).length > 0 && (
          <DetailSection label="CIP/EtherNet/IP Analysis">
            {eventAttrs["service_name"] != null && (
              <DetailRow label="Service" value={String(eventAttrs["service_name"])} mono />
            )}
            {eventAttrs["object_class_name"] != null && (
              <DetailRow label="Object Class" value={String(eventAttrs["object_class_name"])} mono />
            )}
            {eventAttrs["address"] != null && (
              <DetailRow label="CIP Path" value={String(eventAttrs["address"])} mono />
            )}
            {eventAttrs["is_write"] === true && (
              <div className="text-xs font-medium text-red-400">WRITE OPERATION</div>
            )}
          </DetailSection>
        )}

        {/* ── Protocol Analysis (BACnet) ── */}
        {isBACnet && Object.keys(eventAttrs).length > 0 && (
          <DetailSection label="BACnet Analysis">
            {eventAttrs["service"] != null && (
              <DetailRow label="Service" value={String(eventAttrs["service"])} mono />
            )}
            {eventAttrs["object_type"] != null && (
              <DetailRow label="Object Type" value={String(eventAttrs["object_type"])} mono />
            )}
            {eventAttrs["object_instance"] != null && (
              <DetailRow label="Object Instance" value={String(eventAttrs["object_instance"])} mono />
            )}
            {eventAttrs["property_id"] != null && (
              <DetailRow label="Property" value={String(eventAttrs["property_id"])} mono />
            )}
            {eventAttrs["is_write"] === true && (
              <div className="text-xs font-medium text-red-400">WRITE OPERATION</div>
            )}
          </DetailSection>
        )}

        {/* Content matches / pattern highlights */}
        {matchedPatterns.length > 0 && (
          <DetailSection label="Matched Patterns">
            <div className="space-y-1">
              {matchedPatterns.map((p, i) => (
                <div key={i} className="rounded-sm border border-red-500/20 bg-red-500/[0.06] px-3 py-1.5 font-mono text-xs text-red-300">
                  <span className="text-red-500/60 mr-2">MATCH</span>
                  <span className="bg-red-500/20 px-1 rounded-sm text-red-200">{p}</span>
                </div>
              ))}
            </div>
          </DetailSection>
        )}

        {/* Hex dump of raw payload */}
        {typeof eventAttrs["raw_hex"] === "string" && (eventAttrs["raw_hex"] as string).length > 0 && (
          <DetailSection label="Raw Packet Data">
            <div className="rounded-sm border border-amber-500/[0.1] bg-[#060808] p-3 font-mono text-[10px] leading-[1.6] overflow-x-auto">
              <div className="flex gap-4 text-[var(--text-dim)] mb-1 border-b border-amber-500/[0.06] pb-1">
                <span className="w-10">OFFSET</span>
                <span className="flex-1">HEX</span>
                <span>ASCII</span>
              </div>
              {formatHexDump(eventAttrs["raw_hex"] as string).map((row, i) => (
                <div key={i} className="flex gap-4">
                  <span className="w-10 text-amber-500/50">{row.offset}</span>
                  <span className="flex-1 text-[var(--text)]">{row.hex}</span>
                  <span className="text-emerald-400/60">{row.ascii}</span>
                </div>
              ))}
            </div>
          </DetailSection>
        )}

        {/* Generic event attributes (for protocols without dedicated section) */}
        {Object.keys(eventAttrs).length > 0 && !isModbus && !isTLS && !isDNP3 && !isS7 && !isCIP && !isBACnet && (
          <DetailSection label="Event Attributes">
            <div className="rounded-sm border border-amber-500/[0.1] bg-[#060808] p-3 font-mono text-[11px] leading-relaxed overflow-x-auto">
              {Object.entries(eventAttrs).filter(([k]) => k !== "raw_hex").map(([key, val]) => {
                const strVal = typeof val === "object" ? JSON.stringify(val) : String(val);
                return (
                  <div key={key} className="flex gap-2">
                    <span className="text-[var(--text-dim)] shrink-0">{key}:</span>
                    <span className="text-[var(--text)]">{strVal}</span>
                  </div>
                );
              })}
            </div>
          </DetailSection>
        )}

        {/* References / CVEs / MITRE */}
        {(refs.length > 0 || cves.length > 0 || mitreIds.length > 0) && (
          <DetailSection label="References">
            {cves.map((c) => (
              <div key={c} className="flex items-center gap-2 text-xs">
                <span className="rounded-sm border border-red-500/20 bg-red-500/10 px-1.5 py-0.5 text-red-400 text-[10px]">CVE</span>
                <span className="text-[var(--text)] font-mono">{c}</span>
              </div>
            ))}
            {mitreIds.map((m) => (
              <div key={m} className="flex items-center gap-2 text-xs">
                <span className="rounded-sm border border-purple-500/20 bg-purple-500/10 px-1.5 py-0.5 text-purple-400 text-[10px]">ATT&CK</span>
                <span className="text-[var(--text)] font-mono">{m}</span>
              </div>
            ))}
            {refs.map((r) => (
              <div key={r} className="text-xs text-amber-400/80 truncate">
                {r.startsWith("http") ? (
                  <a href={r} target="_blank" rel="noopener noreferrer" className="hover:text-amber-300 underline">{r}</a>
                ) : r}
              </div>
            ))}
          </DetailSection>
        )}

        {/* Labels */}
        {Object.keys(labels).length > 0 && (
          <DetailSection label="Labels">
            {Object.entries(labels).map(([k, v]) => (
              <DetailRow key={k} label={k} value={v || "true"} mono />
            ))}
          </DetailSection>
        )}
      </div>
    </div>
  );
}

function DetailSection({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="border-b border-amber-500/[0.06] px-4 py-3">
      <div className="mb-2 flex items-center gap-2 text-[9px] font-medium uppercase tracking-[2px] text-[var(--text-dim)]">
        {label}
        <span className="flex-1 h-px bg-amber-500/[0.08]" />
      </div>
      <div className="space-y-1.5">{children}</div>
    </div>
  );
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-3 text-xs">
      <span className="text-[var(--text-dim)] shrink-0">{label}</span>
      <span className={`text-right text-[var(--text)] break-all ${mono ? "font-mono text-[11px]" : ""}`}>{value}</span>
    </div>
  );
}
