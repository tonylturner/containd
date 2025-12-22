"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Terminal } from "xterm";
import { FitAddon } from "xterm-addon-fit";
import "xterm/css/xterm.css";

import { getSessionToken } from "../lib/api";

type CLIResponse = { output?: string; error?: string };

export function Console({ prompt = "containd# " }: { prompt?: string }) {
  const [connected, setConnected] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const lineRef = useRef("");
  const historyRef = useRef<string[]>([]);
  const histPosRef = useRef(-1);
  const busyRef = useRef(false);

  const wsURL = useMemo(() => {
    if (typeof window === "undefined") return "";
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const token = getSessionToken();
    const base = `${proto}://${window.location.host}/api/v1/cli/ws`;
    return token ? `${base}?token=${encodeURIComponent(token)}` : base;
  }, []);

  useEffect(() => {
    if (!containerRef.current) return;
    const term = new Terminal({
      cursorBlink: true,
      fontSize: 12,
      scrollback: 2000,
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
      theme: {
        background: "transparent",
        foreground: "#e2e8f0",
      },
    });
    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(containerRef.current);
    fitAddon.fit();

    termRef.current = term;
    fitRef.current = fitAddon;

    function writePrompt() {
      term.write(`\r\n${prompt}`);
    }

    function writeOutput(text: string) {
      if (!text) return;
      const normalized = text.replace(/\r?\n/g, "\r\n");
      term.write(normalized);
      if (!normalized.endsWith("\r\n")) {
        term.write("\r\n");
      }
    }

    function writeError(text: string) {
      if (!text) return;
      term.write(`\x1b[33m${text}\x1b[0m\r\n`);
    }

    function resetLine(value: string) {
      term.write("\x1b[2K\r");
      term.write(prompt + value);
      lineRef.current = value;
    }

    function sendLine(cmd: string) {
      const ws = wsRef.current;
      if (!ws || ws.readyState !== WebSocket.OPEN) {
        writeError("Console not connected.");
        writePrompt();
        return;
      }
      busyRef.current = true;
      ws.send(JSON.stringify({ line: cmd }));
    }

    term.onKey(({ key, domEvent }) => {
      if (busyRef.current) return;
      const ev = domEvent;
      if (ev.key === "Enter") {
        const line = lineRef.current.trim();
        term.write("\r\n");
        histPosRef.current = -1;
        if (!line) {
          writePrompt();
          return;
        }
        if (line === "clear" || line === "cls") {
          term.clear();
          lineRef.current = "";
          writePrompt();
          return;
        }
        const history = historyRef.current;
        history.unshift(line);
        historyRef.current = history.slice(0, 50);
        lineRef.current = "";
        sendLine(line);
        return;
      }
      if (ev.key === "Backspace") {
        if (lineRef.current.length > 0) {
          lineRef.current = lineRef.current.slice(0, -1);
          term.write("\b \b");
        }
        return;
      }
      if (ev.key === "ArrowUp") {
        ev.preventDefault();
        const next = Math.min(histPosRef.current + 1, historyRef.current.length - 1);
        if (next >= 0) {
          histPosRef.current = next;
          resetLine(historyRef.current[next]);
        }
        return;
      }
      if (ev.key === "ArrowDown") {
        ev.preventDefault();
        const next = histPosRef.current - 1;
        if (next < 0) {
          histPosRef.current = -1;
          resetLine("");
        } else {
          histPosRef.current = next;
          resetLine(historyRef.current[next] ?? "");
        }
        return;
      }
      if (ev.ctrlKey || ev.metaKey || ev.altKey) return;
      if (key.length === 1) {
        lineRef.current += key;
        term.write(key);
      }
    });

    const onResize = () => fitAddon.fit();
    window.addEventListener("resize", onResize);

    return () => {
      window.removeEventListener("resize", onResize);
      term.dispose();
    };
  }, [prompt]);

  useEffect(() => {
    if (!wsURL) return;
    const term = termRef.current;
    if (!term) return;
    const ws = new WebSocket(wsURL);
    wsRef.current = ws;
    setStatusMsg(null);

    ws.onopen = () => {
      setConnected(true);
      term.writeln("containd in-app CLI. Type 'show version'.");
      term.write(prompt);
    };

    ws.onmessage = (ev) => {
      busyRef.current = false;
      let payload: CLIResponse | null = null;
      try {
        payload = JSON.parse(ev.data);
      } catch {
        payload = { output: String(ev.data ?? "") };
      }
      if (payload?.output) {
        const normalized = payload.output.replace(/\r?\n/g, "\r\n");
        term.write(normalized);
        if (!normalized.endsWith("\r\n")) {
          term.write("\r\n");
        }
      }
      if (payload?.error) {
        term.write(`\x1b[33m${payload.error}\x1b[0m\r\n`);
      }
      term.write(prompt);
    };

    ws.onclose = () => {
      setConnected(false);
      setStatusMsg("Disconnected. Refresh to reconnect.");
    };

    ws.onerror = () => {
      setStatusMsg("Console connection error.");
    };

    return () => {
      ws.close();
    };
  }, [prompt, wsURL]);

  return (
    <div className="rounded-2xl border border-white/10 bg-black/40 p-4 shadow-inner backdrop-blur">
      <div className="mb-3 flex items-center justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.2em] text-slate-300">
            In-app console
          </p>
          <h2 className="text-xl font-semibold text-white">CLI</h2>
        </div>
        <div className="text-xs text-slate-400">
          Enter to run · ↑/↓ history · clear to reset
        </div>
      </div>

      <div className="h-64 overflow-hidden rounded-lg border border-white/5 bg-black/60 px-2 py-2">
        <div ref={containerRef} className="h-full w-full" />
      </div>

      <div className="mt-2 text-xs text-slate-400">
        {statusMsg ?? (connected ? "Connected" : "Connecting…")}
      </div>
    </div>
  );
}
