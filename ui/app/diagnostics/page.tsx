"use client";

import { useEffect, useMemo, useState } from "react";

import { api, isAdmin, type Interface, type InterfaceState } from "../../lib/api";
import { Shell } from "../../components/Shell";
import { Card } from "../../components/Card";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";

type CmdResult = {
  output: string;
  error?: string;
};

function parseDurationMillis(s: string): number | null {
  const m = s.trim().match(/^([0-9]+(?:\.[0-9]+)?)(ms|s)$/i);
  if (!m) return null;
  const n = Number(m[1]);
  if (!Number.isFinite(n)) return null;
  const unit = m[2].toLowerCase();
  return unit === "s" ? n * 1000 : n;
}

function parsePing(output: string): { samplesMs: number[]; minMs?: number; avgMs?: number; maxMs?: number } {
  const samplesMs: number[] = [];
  const lines = output.split("\n");
  for (const line of lines) {
    const m = line.match(/\btime=([0-9.]+(?:ms|s))\b/i);
    if (m) {
      const ms = parseDurationMillis(m[1]);
      if (ms != null) samplesMs.push(ms);
    }
  }
  let minMs: number | undefined;
  let avgMs: number | undefined;
  let maxMs: number | undefined;
  for (const line of lines) {
    const m = line.match(/min\/avg\/max\s*=\s*([0-9.]+(?:ms|s))\/([0-9.]+(?:ms|s))\/([0-9.]+(?:ms|s))/i);
    if (!m) continue;
    minMs = parseDurationMillis(m[1]) ?? undefined;
    avgMs = parseDurationMillis(m[2]) ?? undefined;
    maxMs = parseDurationMillis(m[3]) ?? undefined;
  }
  return { samplesMs, minMs, avgMs, maxMs };
}

type Hop = { ttl: number; peer?: string; probes: (string | null)[]; raw: string };

function parseTraceroute(output: string): Hop[] {
  const hops: Hop[] = [];
  const lines = output.split("\n");
  for (const line of lines) {
    const m = line.match(/^\s*(\d+)\s+(.*)$/);
    if (!m) continue;
    const ttl = Number(m[1]);
    if (!Number.isFinite(ttl)) continue;
    const rest = m[2].trim();
    if (!rest) continue;

    const tokens = rest.split(/\s+/);
    let peer: string | undefined;
    const probes: (string | null)[] = [];
    for (const tok of tokens) {
      if (!peer && tok.includes(".") && tok !== "*") peer = tok;
      if (tok === "*") probes.push(null);
      else if (tok.match(/^[0-9.]+(?:ms|s)$/i)) probes.push(tok);
    }
    // Ensure 3 columns.
    while (probes.length < 3) probes.push(null);
    hops.push({ ttl, peer, probes: probes.slice(0, 3), raw: line });
  }
  return hops;
}

function smallSpark(values: number[]): JSX.Element {
  if (values.length === 0) return <span className="text-slate-400">—</span>;
  const max = Math.max(...values);
  const min = Math.min(...values);
  const span = Math.max(1, max - min);
  return (
    <div className="flex h-6 items-end gap-1">
      {values.slice(-12).map((v, idx) => {
        const h = Math.max(2, Math.round(((v - min) / span) * 22));
        return (
          <div
            key={idx}
            className="w-2 rounded-sm bg-blue-500/40"
            style={{ height: `${h}px` }}
            title={`${v.toFixed(1)}ms`}
          />
        );
      })}
    </div>
  );
}

async function runCLI(line: string): Promise<CmdResult> {
  const res = await api.executeCLI(line);
  return { output: res?.output ?? "", error: res?.error || undefined };
}

function firstIPv4(addrs: string[] | undefined | null): string | null {
  for (const a of addrs ?? []) {
    const s = a.trim();
    if (!s) continue;
    const ip = s.split("/")[0]?.trim();
    if (!ip) continue;
    if (ip.split(".").length === 4) return ip;
  }
  return null;
}

function isIPv4(input: string): boolean {
  const s = input.trim();
  if (!s) return false;
  const parts = s.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    if (!p.match(/^[0-9]+$/)) return false;
    const n = Number(p);
    return Number.isInteger(n) && n >= 0 && n <= 255;
  });
}

export default function DiagnosticsPage() {
  const canEdit = isAdmin();
  const confirm = useConfirm();
  const [ifaces, setIfaces] = useState<Interface[]>([]);
  const [state, setState] = useState<InterfaceState[]>([]);
  const [busy, setBusy] = useState<string | null>(null);

  const [pingHost, setPingHost] = useState("8.8.8.8");
  const [pingCount, setPingCount] = useState(4);
  const [pingRes, setPingRes] = useState<CmdResult | null>(null);

  const [traceHost, setTraceHost] = useState("google.com");
  const [traceHops, setTraceHops] = useState(20);
  const [traceRes, setTraceRes] = useState<CmdResult | null>(null);

  const [tcpTraceHost, setTCPTraceHost] = useState("google.com");
  const [tcpTracePort, setTCPTracePort] = useState(443);
  const [tcpTraceHops, setTCPTraceHops] = useState(20);
  const [tcpTraceRes, setTCPTraceRes] = useState<CmdResult | null>(null);

  const [reachSrc, setReachSrc] = useState("lan1");
  const [reachDst, setReachDst] = useState("");
  const [reachProto, setReachProto] = useState<"tcp" | "udp" | "icmp">("tcp");
  const [reachSelfTest, setReachSelfTest] = useState(false);
  const [reachDstIface, setReachDstIface] = useState("wan");
  const [reachPort, setReachPort] = useState<string>("");
  const [reachRes, setReachRes] = useState<CmdResult | null>(null);

  const [blockHostIP, setBlockHostIP] = useState("");
  const [blockHostTTL, setBlockHostTTL] = useState("300");
  const [blockFlowSrc, setBlockFlowSrc] = useState("");
  const [blockFlowDst, setBlockFlowDst] = useState("");
  const [blockFlowProto, setBlockFlowProto] = useState<"tcp" | "udp">("tcp");
  const [blockFlowPort, setBlockFlowPort] = useState("502");
  const [blockFlowTTL, setBlockFlowTTL] = useState("300");
  const [blockMsg, setBlockMsg] = useState<string | null>(null);
  const [blockErr, setBlockErr] = useState<string | null>(null);

  const dstInterfaceChoices = useMemo(() => {
    const byName = new Map(state.map((s) => [s.name, s] as const));
    return ifaces
      .slice()
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((i) => {
        const dev = (i.device || i.name).trim();
        const alias = i.alias?.trim();
        const st = byName.get(dev);
        const baseLabel = `${i.name}${dev && dev !== i.name ? ` (${dev})` : ""}`;
        return {
          label: alias ? `${alias} (${baseLabel})` : baseLabel,
          value: i.name,
          ip: firstIPv4(st?.addrs),
        };
      });
  }, [ifaces, state]);

  useEffect(() => {
    (async () => {
      const [i, s] = await Promise.all([api.listInterfaces(), api.listInterfaceState()]);
      setIfaces(i ?? []);
      setState(s ?? []);
    })();
  }, []);

  const pingParsed = useMemo(() => (pingRes ? parsePing(pingRes.output) : null), [pingRes]);
  const traceParsed = useMemo(() => (traceRes ? parseTraceroute(traceRes.output) : []), [traceRes]);
  const tcpTraceParsed = useMemo(
    () => (tcpTraceRes ? parseTraceroute(tcpTraceRes.output) : []),
    [tcpTraceRes],
  );
  const blockDisabled = !canEdit || busy !== null;

  return (
    <Shell title="Diagnostics">
      <ConfirmDialog {...confirm.props} />
      <div className="mb-4 rounded-xl border border-white/[0.08] bg-white/[0.03] px-4 py-3 text-sm text-slate-200 shadow-card">
        Diagnostics run from the appliance. In container labs, ICMP may be blocked; <span className="font-semibold">diag ping</span>{" "}
        falls back to TCP probes when needed.
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Ping" padding="lg">
          <div className="grid gap-3 md:grid-cols-3">
            <input
              value={pingHost}
              onChange={(e) => setPingHost(e.target.value)}
              placeholder="host or IP"
              className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none md:col-span-2"
            />
            <input
              value={String(pingCount)}
              onChange={(e) => setPingCount(Math.max(1, Math.min(20, Number(e.target.value) || 1)))}
              placeholder="count"
              className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
            />
          </div>
          <div className="mt-3 flex items-center justify-between">
            <div className="text-xs text-slate-400">Command: `diag ping {pingHost} {pingCount}`</div>
            <button
              type="button"
              disabled={busy !== null}
              onClick={async () => {
                setBusy("ping");
                setPingRes(await runCLI(`diag ping ${pingHost} ${pingCount}`));
                setBusy(null);
              }}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 transition-ui disabled:opacity-50"
            >
              {busy === "ping" ? "Running..." : "Run"}
            </button>
          </div>
          {pingRes && (
            <div className="mt-4 rounded-xl border border-white/[0.08] bg-black/30 p-4">
              {pingRes.error && (
                <div className="mb-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-400">
                  {pingRes.error}
                </div>
              )}
              {pingParsed && (
                <div className="mb-3 grid gap-2 md:grid-cols-3">
                  <div className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-2">
                    <div className="text-xs text-slate-400">Samples</div>
                    <div className="text-sm text-white">{pingParsed.samplesMs.length}</div>
                  </div>
                  <div className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-2">
                    <div className="text-xs text-slate-400">min/avg/max</div>
                    <div className="text-sm text-white">
                      {(pingParsed.minMs ?? 0).toFixed(0)} / {(pingParsed.avgMs ?? 0).toFixed(0)} /{" "}
                      {(pingParsed.maxMs ?? 0).toFixed(0)} ms
                    </div>
                  </div>
                  <div className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-2">
                    <div className="text-xs text-slate-400">Trend</div>
                    {smallSpark(pingParsed.samplesMs)}
                  </div>
                </div>
              )}
              <pre className="max-h-64 overflow-auto whitespace-pre-wrap text-xs text-slate-200">{pingRes.output}</pre>
            </div>
          )}
        </Card>

        <Card title="Traceroute" padding="lg">
          <div className="grid gap-3 md:grid-cols-3">
            <input
              value={traceHost}
              onChange={(e) => setTraceHost(e.target.value)}
              placeholder="host or IP"
              className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none md:col-span-2"
            />
            <input
              value={String(traceHops)}
              onChange={(e) => setTraceHops(Math.max(1, Math.min(64, Number(e.target.value) || 20)))}
              placeholder="max hops"
              className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
            />
          </div>
          <div className="mt-3 flex items-center justify-between">
            <div className="text-xs text-slate-400">Command: `diag traceroute {traceHost} {traceHops}`</div>
            <button
              type="button"
              disabled={busy !== null}
              onClick={async () => {
                setBusy("trace");
                setTraceRes(await runCLI(`diag traceroute ${traceHost} ${traceHops}`));
                setBusy(null);
              }}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 transition-ui disabled:opacity-50"
            >
              {busy === "trace" ? "Running..." : "Run"}
            </button>
          </div>
          {traceRes && (
            <div className="mt-4 rounded-xl border border-white/[0.08] bg-black/30 p-4">
              {traceRes.error && (
                <div className="mb-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-400">
                  {traceRes.error}
                </div>
              )}
              {traceParsed.length > 0 && (
                <div className="mb-3 overflow-hidden rounded-lg border border-white/[0.08]">
                  <table className="w-full text-xs">
                    <thead className="bg-black/40 text-left text-[11px] uppercase tracking-wide text-slate-300">
                      <tr>
                        <th className="px-3 py-2">Hop</th>
                        <th className="px-3 py-2">Peer</th>
                        <th className="px-3 py-2">P1</th>
                        <th className="px-3 py-2">P2</th>
                        <th className="px-3 py-2">P3</th>
                      </tr>
                    </thead>
                    <tbody>
                      {traceParsed.slice(0, 24).map((h) => (
                        <tr key={h.ttl} className="border-t border-white/[0.06] table-row-hover transition-ui">
                          <td className="px-3 py-2 text-slate-200">{h.ttl}</td>
                          <td className="px-3 py-2 text-slate-200">{h.peer ?? "—"}</td>
                          {h.probes.map((p, idx) => (
                            <td key={idx} className="px-3 py-2 text-slate-200">
                              {p ?? "*"}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <pre className="max-h-64 overflow-auto whitespace-pre-wrap text-xs text-slate-200">{traceRes.output}</pre>
            </div>
          )}
        </Card>

        <Card title="TCP Traceroute" padding="lg">
          <div className="grid gap-3 md:grid-cols-3">
            <input
              value={tcpTraceHost}
              onChange={(e) => setTCPTraceHost(e.target.value)}
              placeholder="host or IP"
              className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
            />
            <input
              value={String(tcpTracePort)}
              onChange={(e) => setTCPTracePort(Math.max(1, Math.min(65535, Number(e.target.value) || 443)))}
              placeholder="port"
              className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
            />
            <input
              value={String(tcpTraceHops)}
              onChange={(e) => setTCPTraceHops(Math.max(1, Math.min(64, Number(e.target.value) || 20)))}
              placeholder="max hops"
              className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
            />
          </div>
          <div className="mt-3 flex items-center justify-between">
            <div className="text-xs text-slate-400">
              Command: `diag tcptraceroute {tcpTraceHost} {tcpTracePort} {tcpTraceHops}`
            </div>
            <button
              type="button"
              disabled={busy !== null}
              onClick={async () => {
                setBusy("tcptrace");
                setTCPTraceRes(await runCLI(`diag tcptraceroute ${tcpTraceHost} ${tcpTracePort} ${tcpTraceHops}`));
                setBusy(null);
              }}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 transition-ui disabled:opacity-50"
            >
              {busy === "tcptrace" ? "Running..." : "Run"}
            </button>
          </div>
          {tcpTraceRes && (
            <div className="mt-4 rounded-xl border border-white/[0.08] bg-black/30 p-4">
              {tcpTraceRes.error && (
                <div className="mb-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-400">
                  {tcpTraceRes.error}
                </div>
              )}
              {tcpTraceParsed.length > 0 && (
                <div className="mb-3 overflow-hidden rounded-lg border border-white/[0.08]">
                  <table className="w-full text-xs">
                    <thead className="bg-black/40 text-left text-[11px] uppercase tracking-wide text-slate-300">
                      <tr>
                        <th className="px-3 py-2">Hop</th>
                        <th className="px-3 py-2">P1</th>
                        <th className="px-3 py-2">P2</th>
                        <th className="px-3 py-2">P3</th>
                      </tr>
                    </thead>
                    <tbody>
                      {tcpTraceParsed.slice(0, 24).map((h) => (
                        <tr key={h.ttl} className="border-t border-white/[0.06] table-row-hover transition-ui">
                          <td className="px-3 py-2 text-slate-200">{h.ttl}</td>
                          {h.probes.map((p, idx) => (
                            <td key={idx} className="px-3 py-2 text-slate-200">
                              {p ?? "*"}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <pre className="max-h-64 overflow-auto whitespace-pre-wrap text-xs text-slate-200">{tcpTraceRes.output}</pre>
            </div>
          )}
        </Card>

        <Card title="Interface Connectivity" padding="lg">
          <div className="text-xs text-slate-400">
            Tests from a selected interface. Use this to validate routing and basic port reachability.
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <div>
              <div className="mb-1 text-xs text-slate-400">Source interface</div>
              <select
                value={reachSrc}
                onChange={(e) => setReachSrc(e.target.value)}
                className="w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
              >
                {ifaces
                  .slice()
                  .sort((a, b) => a.name.localeCompare(b.name))
                  .map((i) => (
                    <option key={i.name} value={i.name}>
                      {i.name}
                    </option>
                  ))}
              </select>
            </div>
            <div>
              <div className="mb-1 text-xs text-slate-400">Destination</div>
              {reachSelfTest ? (
                <>
                  <select
                    value={reachDstIface}
                    onChange={(e) => setReachDstIface(e.target.value)}
                    className="w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
                  >
                    {ifaces
                      .slice()
                      .sort((a, b) => a.name.localeCompare(b.name))
                      .map((i) => (
                        <option key={i.name} value={i.name}>
                          {i.name}
                        </option>
                      ))}
                  </select>
                  <div className="mt-1 text-[11px] text-slate-400">
                    Self-test runs a temporary listener on the destination interface so TCP/UDP can be validated even when
                    nothing is running.
                  </div>
                </>
              ) : (
                <>
                  <input
                    value={reachDst}
                    onChange={(e) => setReachDst(e.target.value)}
                    placeholder="host, IP, or interface name"
                    className="w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
                  />
                  <div className="mt-1 text-[11px] text-slate-400">
                    Tip: set this to another interface name (e.g. <span className="text-slate-200">wan</span>) for a
                    deterministic self-test, or an IP/host for best-effort probing.
                  </div>
                </>
              )}
            </div>
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <div>
              <div className="mb-1 text-xs text-slate-400">Protocol</div>
              <select
                value={reachProto}
                onChange={(e) => {
                  const v = e.target.value as "tcp" | "udp" | "icmp";
                  setReachProto(v);
                  if (v === "icmp") setReachPort("");
                  if (v === "icmp") setReachSelfTest(false);
                }}
                className="w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
              >
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
                <option value="icmp">icmp</option>
              </select>
              <label className="mt-2 flex items-center gap-2 text-[11px] text-slate-300">
                <input
                  type="checkbox"
                  checked={reachSelfTest}
                  disabled={reachProto === "icmp"}
                  onChange={(e) => setReachSelfTest(e.target.checked)}
                />
                Self-test (dst interface)
                <span className="text-slate-500">
                  {reachProto === "icmp" ? "(not applicable)" : "(recommended for interface↔interface checks)"}
                </span>
              </label>
            </div>
            <div>
              <div className="mb-1 text-xs text-slate-400">Port (tcp/udp only; optional)</div>
              <input
                value={reachPort}
                disabled={reachProto === "icmp"}
                onChange={(e) => {
                  if (reachProto === "icmp") return;
                  const v = e.target.value;
                  if (v === "") {
                    setReachPort("");
                    return;
                  }
                  // Only allow digits; keep UX simple.
                  if (!v.match(/^[0-9]+$/)) return;
                  const n = Number(v);
                  if (!Number.isFinite(n) || n < 1 || n > 65535) return;
                  setReachPort(String(n));
                }}
                placeholder={
                  reachProto === "icmp"
                    ? "N/A for ICMP"
                    : "blank = skip (or self-test if dst is an interface name)"
                }
                className="w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none disabled:opacity-60"
              />
            </div>
          </div>
          <div className="mt-3 flex items-end justify-between gap-2">
            <div className="text-[11px] text-slate-400">
              Uses `diag reach` (new).
              {dstInterfaceChoices.length > 0 ? (
                <div className="mt-1">
                  Quick pick:
                  {dstInterfaceChoices.slice(0, 4).map((c) => (
                    <button
                      key={c.value}
                      type="button"
                      className="ml-2 rounded-md bg-white/[0.03] px-2 py-1 text-[11px] text-slate-200 hover:bg-white/[0.08] transition-ui"
                      onClick={() => {
                        if (reachSelfTest) {
                          setReachDstIface(c.value);
                          return;
                        }
                        setReachDst(c.ip ? c.ip : c.value);
                      }}
                      title={c.ip ? `Use ${c.value} OS/Docker IP: ${c.ip}` : `Use ${c.value}`}
                    >
                      {c.value}
                    </button>
                  ))}
                </div>
              ) : null}
            </div>
            <button
              type="button"
              disabled={busy !== null}
              onClick={async () => {
                const dst = reachSelfTest ? reachDstIface.trim() : reachDst.trim();
                if (!dst) return;
                setBusy("reach");
                const portArg = reachPort.trim();
                let line = `diag reach ${reachSrc} ${dst} ${reachProto}`;
                if (reachProto !== "icmp" && portArg) line += ` ${portArg}`;
                setReachRes(await runCLI(line));
                setBusy(null);
              }}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 transition-ui disabled:opacity-50"
            >
              {busy === "reach" ? "Running..." : "Run"}
            </button>
          </div>
          {reachRes && (
            <div className="mt-4 rounded-xl border border-white/[0.08] bg-black/30 p-4">
              {reachRes.error && (
                <div className="mb-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-400">
                  {reachRes.error}
                </div>
              )}
              <pre className="max-h-64 overflow-auto whitespace-pre-wrap text-xs text-slate-200">{reachRes.output}</pre>
              {!isAdmin() && (
                <div className="mt-2 text-[11px] text-slate-400">
                  Some diagnostics (like packet capture) require admin.
                </div>
              )}
            </div>
          )}
        </Card>

        <Card title="Temporary Blocks" padding="lg">
          <div className="text-xs text-slate-400">
            Push short-lived blocks into nftables. These are best-effort and expire automatically.
          </div>
          {!canEdit && (
            <div className="mt-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-400">
              Admin access required to apply blocks.
            </div>
          )}
          <div className="mt-4 grid gap-4">
            <div className="rounded-xl border border-white/[0.08] bg-black/30 p-4">
              <div className="text-xs uppercase tracking-wide text-slate-400">Block Host</div>
              <div className="mt-3 grid gap-3 md:grid-cols-3">
                <input
                  value={blockHostIP}
                  onChange={(e) => setBlockHostIP(e.target.value)}
                  placeholder="source or destination IP"
                  className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none md:col-span-2"
                />
                <input
                  value={blockHostTTL}
                  onChange={(e) => {
                    const v = e.target.value;
                    if (v === "" || v.match(/^[0-9]+$/)) setBlockHostTTL(v);
                  }}
                  placeholder="ttl (seconds)"
                  className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
                />
              </div>
              <div className="mt-3 flex items-center justify-between gap-2">
                <div className="text-xs text-slate-400">Blocks any flow matching this IP.</div>
                <button
                  type="button"
                  disabled={blockDisabled}
                  onClick={() => {
                    if (!blockHostIP.trim()) return;
                    if (!isIPv4(blockHostIP)) {
                      setBlockErr("Enter a valid IPv4 address for host block.");
                      setBlockMsg(null);
                      return;
                    }
                    confirm.open({
                      title: "Block Host",
                      message: `Block all traffic matching IP ${blockHostIP.trim()}?`,
                      confirmLabel: "Block",
                      variant: "warning",
                      onConfirm: async () => {
                        setBlockErr(null);
                        setBlockMsg(null);
                        setBusy("block-host");
                        const ttl = blockHostTTL.trim() ? Number(blockHostTTL.trim()) : 0;
                        const res = await api.blockHostTemp(blockHostIP.trim(), Number.isFinite(ttl) ? ttl : undefined);
                        if (!res) setBlockErr("Failed to apply host block.");
                        else setBlockMsg(`Blocked host ${blockHostIP.trim()}.`);
                        setBusy(null);
                      },
                    });
                  }}
                  className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 transition-ui disabled:opacity-50"
                >
                  {busy === "block-host" ? "Applying..." : "Block host"}
                </button>
              </div>
            </div>

            <div className="rounded-xl border border-white/[0.08] bg-black/30 p-4">
              <div className="text-xs uppercase tracking-wide text-slate-400">Block Flow</div>
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                <input
                  value={blockFlowSrc}
                  onChange={(e) => setBlockFlowSrc(e.target.value)}
                  placeholder="source IP"
                  className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
                />
                <input
                  value={blockFlowDst}
                  onChange={(e) => setBlockFlowDst(e.target.value)}
                  placeholder="destination IP"
                  className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
                />
              </div>
              <div className="mt-3 grid gap-3 md:grid-cols-3">
                <select
                  value={blockFlowProto}
                  onChange={(e) => setBlockFlowProto(e.target.value as "tcp" | "udp")}
                  className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
                >
                  <option value="tcp">tcp</option>
                  <option value="udp">udp</option>
                </select>
                <input
                  value={blockFlowPort}
                  onChange={(e) => {
                    const v = e.target.value;
                    if (v === "" || v.match(/^[0-9]+$/)) setBlockFlowPort(v);
                  }}
                  placeholder="dst port"
                  className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
                />
                <input
                  value={blockFlowTTL}
                  onChange={(e) => {
                    const v = e.target.value;
                    if (v === "" || v.match(/^[0-9]+$/)) setBlockFlowTTL(v);
                  }}
                  placeholder="ttl (seconds)"
                  className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
                />
              </div>
              <div className="mt-3 flex items-center justify-between gap-2">
                <div className="text-xs text-slate-400">Blocks a specific 5-tuple (src/dst/port/proto).</div>
                <button
                  type="button"
                  disabled={blockDisabled}
                  onClick={() => {
                    if (!blockFlowSrc.trim() || !blockFlowDst.trim() || !blockFlowPort.trim()) return;
                    if (!isIPv4(blockFlowSrc) || !isIPv4(blockFlowDst)) {
                      setBlockErr("Enter valid IPv4 addresses for flow block.");
                      setBlockMsg(null);
                      return;
                    }
                    const portNum = Number(blockFlowPort.trim());
                    if (!Number.isFinite(portNum) || portNum < 1 || portNum > 65535) {
                      setBlockErr("Enter a valid destination port (1-65535).");
                      setBlockMsg(null);
                      return;
                    }
                    confirm.open({
                      title: "Block Flow",
                      message: `Block flow ${blockFlowSrc.trim()} -> ${blockFlowDst.trim()}:${blockFlowPort.trim()} (${blockFlowProto})?`,
                      confirmLabel: "Block",
                      variant: "warning",
                      onConfirm: async () => {
                        setBlockErr(null);
                        setBlockMsg(null);
                        setBusy("block-flow");
                        const ttl = blockFlowTTL.trim() ? Number(blockFlowTTL.trim()) : 0;
                        const res = await api.blockFlowTemp({
                          srcIp: blockFlowSrc.trim(),
                          dstIp: blockFlowDst.trim(),
                          proto: blockFlowProto,
                          dstPort: blockFlowPort.trim(),
                          ttlSeconds: Number.isFinite(ttl) ? ttl : undefined,
                        });
                        if (!res) setBlockErr("Failed to apply flow block.");
                        else setBlockMsg(`Blocked flow ${blockFlowSrc.trim()} -> ${blockFlowDst.trim()}:${blockFlowPort.trim()}.`);
                        setBusy(null);
                      },
                    });
                  }}
                  className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 transition-ui disabled:opacity-50"
                >
                  {busy === "block-flow" ? "Applying..." : "Block flow"}
                </button>
              </div>
            </div>
          </div>
          {(blockMsg || blockErr) && (
            <div className="mt-4 space-y-2">
              {blockErr && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
                  {blockErr}
                </div>
              )}
              {blockMsg && (
                <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-400">
                  {blockMsg}
                </div>
              )}
            </div>
          )}
        </Card>
      </div>
    </Shell>
  );
}
