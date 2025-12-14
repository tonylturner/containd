"use client";

import { useEffect, useMemo, useState } from "react";

import { api, isAdmin, type Interface, type InterfaceState } from "../../lib/api";
import { Shell } from "../../components/Shell";

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
            className="w-2 rounded-sm bg-mint/40"
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

export default function DiagnosticsPage() {
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
  const [reachPort, setReachPort] = useState<number>(443);
  const [reachRes, setReachRes] = useState<CmdResult | null>(null);

  const dstInterfaceChoices = useMemo(() => {
    const byName = new Map(state.map((s) => [s.name, s] as const));
    return ifaces
      .slice()
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((i) => {
        const dev = (i.device || i.name).trim();
        const st = byName.get(dev);
        return {
          label: `${i.name}${dev && dev !== i.name ? ` (${dev})` : ""}`,
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

  return (
    <Shell title="Diagnostics">
      <div className="mb-4 rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-200">
        Diagnostics run from the appliance. In container labs, ICMP may be blocked; <span className="font-semibold">diag ping</span>{" "}
        falls back to TCP probes when needed.
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
          <h2 className="text-sm font-semibold text-white">Ping</h2>
          <div className="mt-3 grid gap-3 md:grid-cols-3">
            <input
              value={pingHost}
              onChange={(e) => setPingHost(e.target.value)}
              placeholder="host or IP"
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500 md:col-span-2"
            />
            <input
              value={String(pingCount)}
              onChange={(e) => setPingCount(Math.max(1, Math.min(20, Number(e.target.value) || 1)))}
              placeholder="count"
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
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
              className="rounded-lg bg-mint/20 px-4 py-2 text-sm font-semibold text-mint hover:bg-mint/30 disabled:opacity-50"
            >
              {busy === "ping" ? "Running..." : "Run"}
            </button>
          </div>
          {pingRes && (
            <div className="mt-4 rounded-xl border border-white/10 bg-black/30 p-4">
              {pingRes.error && (
                <div className="mb-3 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
                  {pingRes.error}
                </div>
              )}
              {pingParsed && (
                <div className="mb-3 grid gap-2 md:grid-cols-3">
                  <div className="rounded-lg border border-white/10 bg-white/5 px-3 py-2">
                    <div className="text-xs text-slate-400">Samples</div>
                    <div className="text-sm text-white">{pingParsed.samplesMs.length}</div>
                  </div>
                  <div className="rounded-lg border border-white/10 bg-white/5 px-3 py-2">
                    <div className="text-xs text-slate-400">min/avg/max</div>
                    <div className="text-sm text-white">
                      {(pingParsed.minMs ?? 0).toFixed(0)} / {(pingParsed.avgMs ?? 0).toFixed(0)} /{" "}
                      {(pingParsed.maxMs ?? 0).toFixed(0)} ms
                    </div>
                  </div>
                  <div className="rounded-lg border border-white/10 bg-white/5 px-3 py-2">
                    <div className="text-xs text-slate-400">Trend</div>
                    {smallSpark(pingParsed.samplesMs)}
                  </div>
                </div>
              )}
              <pre className="max-h-64 overflow-auto whitespace-pre-wrap text-xs text-slate-200">{pingRes.output}</pre>
            </div>
          )}
        </div>

        <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
          <h2 className="text-sm font-semibold text-white">Traceroute</h2>
          <div className="mt-3 grid gap-3 md:grid-cols-3">
            <input
              value={traceHost}
              onChange={(e) => setTraceHost(e.target.value)}
              placeholder="host or IP"
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500 md:col-span-2"
            />
            <input
              value={String(traceHops)}
              onChange={(e) => setTraceHops(Math.max(1, Math.min(64, Number(e.target.value) || 20)))}
              placeholder="max hops"
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
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
              className="rounded-lg bg-mint/20 px-4 py-2 text-sm font-semibold text-mint hover:bg-mint/30 disabled:opacity-50"
            >
              {busy === "trace" ? "Running..." : "Run"}
            </button>
          </div>
          {traceRes && (
            <div className="mt-4 rounded-xl border border-white/10 bg-black/30 p-4">
              {traceRes.error && (
                <div className="mb-3 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
                  {traceRes.error}
                </div>
              )}
              {traceParsed.length > 0 && (
                <div className="mb-3 overflow-hidden rounded-lg border border-white/10">
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
                        <tr key={h.ttl} className="border-t border-white/5">
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
        </div>

        <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
          <h2 className="text-sm font-semibold text-white">TCP Traceroute</h2>
          <div className="mt-3 grid gap-3 md:grid-cols-3">
            <input
              value={tcpTraceHost}
              onChange={(e) => setTCPTraceHost(e.target.value)}
              placeholder="host or IP"
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
            />
            <input
              value={String(tcpTracePort)}
              onChange={(e) => setTCPTracePort(Math.max(1, Math.min(65535, Number(e.target.value) || 443)))}
              placeholder="port"
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
            />
            <input
              value={String(tcpTraceHops)}
              onChange={(e) => setTCPTraceHops(Math.max(1, Math.min(64, Number(e.target.value) || 20)))}
              placeholder="max hops"
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
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
              className="rounded-lg bg-mint/20 px-4 py-2 text-sm font-semibold text-mint hover:bg-mint/30 disabled:opacity-50"
            >
              {busy === "tcptrace" ? "Running..." : "Run"}
            </button>
          </div>
          {tcpTraceRes && (
            <div className="mt-4 rounded-xl border border-white/10 bg-black/30 p-4">
              {tcpTraceRes.error && (
                <div className="mb-3 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
                  {tcpTraceRes.error}
                </div>
              )}
              {tcpTraceParsed.length > 0 && (
                <div className="mb-3 overflow-hidden rounded-lg border border-white/10">
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
                        <tr key={h.ttl} className="border-t border-white/5">
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
        </div>

        <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
          <h2 className="text-sm font-semibold text-white">Interface Connectivity</h2>
          <div className="mt-1 text-xs text-slate-400">
            Tests from a selected interface. Use this to validate routing and basic port reachability.
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <div>
              <div className="mb-1 text-xs text-slate-400">Source interface</div>
              <select
                value={reachSrc}
                onChange={(e) => setReachSrc(e.target.value)}
                className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
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
              <input
                value={reachDst}
                onChange={(e) => setReachDst(e.target.value)}
                placeholder="host, IP, or interface name"
                className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
              />
              <div className="mt-1 text-[11px] text-slate-400">
                Tip: set this to another interface name (e.g. <span className="text-slate-200">wan</span>) or an IP.
              </div>
            </div>
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <div>
              <div className="mb-1 text-xs text-slate-400">TCP port (optional)</div>
              <input
                value={String(reachPort)}
                onChange={(e) => setReachPort(Math.max(1, Math.min(65535, Number(e.target.value) || 443)))}
                className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
              />
            </div>
            <div className="flex items-end justify-between gap-2">
              <div className="text-[11px] text-slate-400">
                Uses `diag reach` (new).
                {dstInterfaceChoices.length > 0 ? (
                  <div className="mt-1">
                    Quick pick:
                    {dstInterfaceChoices.slice(0, 4).map((c) => (
                      <button
                        key={c.value}
                        type="button"
                        className="ml-2 rounded-md bg-white/5 px-2 py-1 text-[11px] text-slate-200 hover:bg-white/10"
                        onClick={() => setReachDst(c.ip ? c.ip : c.value)}
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
                  const dst = reachDst.trim();
                  if (!dst) return;
                  setBusy("reach");
                  const line = `diag reach ${reachSrc} ${dst} ${reachPort}`;
                  setReachRes(await runCLI(line));
                  setBusy(null);
                }}
                className="rounded-lg bg-mint/20 px-4 py-2 text-sm font-semibold text-mint hover:bg-mint/30 disabled:opacity-50"
              >
                {busy === "reach" ? "Running..." : "Run"}
              </button>
            </div>
          </div>
          {reachRes && (
            <div className="mt-4 rounded-xl border border-white/10 bg-black/30 p-4">
              {reachRes.error && (
                <div className="mb-3 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
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
        </div>
      </div>
    </Shell>
  );
}

