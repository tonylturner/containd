"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { Terminal } from "xterm";
import type { FitAddon } from "xterm-addon-fit";
import "xterm/css/xterm.css";

import { api, getSessionToken } from "../lib/api";
import { getPersistCLIHistory } from "../lib/prefs";

type CLIResponse = { output?: string; error?: string };

export function Console({ prompt = "containd# " }: { prompt?: string }) {
  const [connected, setConnected] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [termReady, setTermReady] = useState(false);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const resizeHandlerRef = useRef<(() => void) | null>(null);
  const lineRef = useRef("");
  const cursorRef = useRef(0);
  const historyRef = useRef<string[]>([]);
  const histPosRef = useRef(-1);
  const busyRef = useRef(false);
  const commandsRef = useRef<string[]>([]);
  const persistHistoryRef = useRef(false);

  const wsURL = useMemo(() => {
    if (typeof window === "undefined") return "";
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const token = getSessionToken();
    const base = `${proto}://${window.location.host}/api/v1/cli/ws`;
    return token ? `${base}?token=${encodeURIComponent(token)}` : base;
  }, []);

  useEffect(() => {
    if (!containerRef.current) return;
    let disposed = false;
    let term: Terminal | null = null;
    let fitAddon: FitAddon | null = null;

    async function initTerminal() {
      persistHistoryRef.current = getPersistCLIHistory();
      if (persistHistoryRef.current && typeof window !== "undefined") {
        try {
          const raw = localStorage.getItem("containd.cli.history");
          if (raw) {
            const list = JSON.parse(raw);
            if (Array.isArray(list)) {
              historyRef.current = list.filter((v) => typeof v === "string").slice(0, 50);
            }
          }
        } catch {}
      }
      const [{ Terminal }, { FitAddon }] = await Promise.all([
        import("xterm"),
        import("xterm-addon-fit"),
      ]);
      if (disposed || !containerRef.current) return;
      term = new Terminal({
        cursorBlink: true,
        fontSize: 12,
        scrollback: 2000,
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
        theme: {
          background: "transparent",
          foreground: "#e2e8f0",
        },
      });
      fitAddon = new FitAddon();
      term.loadAddon(fitAddon);
      term.open(containerRef.current);
      fitAddon.fit();

      termRef.current = term;
      fitRef.current = fitAddon;
      setTermReady(true);

      function writePrompt() {
        term?.write(`\r\n${prompt}`);
        lineRef.current = "";
        cursorRef.current = 0;
      }

      function writeOutput(text: string) {
        if (!text || !term) return;
        const normalized = text.replace(/\r?\n/g, "\r\n");
        term.write(normalized);
        if (!normalized.endsWith("\r\n")) {
          term.write("\r\n");
        }
      }

      function writeError(text: string) {
        if (!text || !term) return;
        term.write(`\x1b[33m${text}\x1b[0m\r\n`);
      }

      function redrawLine() {
        if (!term) return;
        term.write("\x1b[2K\r");
        term.write(prompt + lineRef.current);
        const moveLeft = lineRef.current.length - cursorRef.current;
        if (moveLeft > 0) {
          term.write(`\x1b[${moveLeft}D`);
        }
      }

      function setLine(value: string) {
        lineRef.current = value;
        cursorRef.current = value.length;
        redrawLine();
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

      function findCommandMatch(line: string) {
        const lower = line.toLowerCase();
        let match = "";
        for (const cmd of commandsRef.current) {
          if (lower === cmd || lower.startsWith(cmd + " ")) {
            if (cmd.length > match.length) match = cmd;
          }
        }
        return match;
      }

      function completeCommandLine() {
        if (!commandsRef.current.length) return false;
        const prefix = lineRef.current.toLowerCase();
        const matches = commandsRef.current.filter((cmd) => cmd.startsWith(prefix));
        if (matches.length === 0) return false;
        if (matches.length === 1) {
          const next = matches[0];
          const suffix = prefix === next ? " " : "";
          setLine(next + suffix);
          return true;
        }
        const shared = matches.reduce((acc, cmd) => {
          let i = 0;
          const max = Math.min(acc.length, cmd.length);
          for (; i < max; i += 1) {
            if (acc[i] !== cmd[i]) break;
          }
          return acc.slice(0, i);
        }, matches[0]);
        if (shared.length > prefix.length) {
          setLine(shared);
          return true;
        }
        term?.write("\r\n" + matches.join("  ") + "\r\n");
        redrawLine();
        return true;
      }

      async function completeArgsLine(lineOverride?: string) {
        const baseLine = lineOverride ?? lineRef.current;
        if (!baseLine.trim()) return;
        const completions = await api.completeCLI(baseLine);
        if (!completions || completions.length === 0) return;
        const lastSpace = baseLine.lastIndexOf(" ");
        const replaceStart = lastSpace >= 0 ? lastSpace + 1 : 0;
        const prefix = baseLine.slice(replaceStart);
        if (completions.length === 1) {
          const next = completions[0];
          setLine(
            baseLine.slice(0, replaceStart) + next + (next.endsWith(" ") ? "" : " "),
          );
          return;
        }
        const matches = completions;
        const shared = matches.reduce((acc, cmd) => {
          let i = 0;
          const max = Math.min(acc.length, cmd.length);
          for (; i < max; i += 1) {
            if (acc[i] !== cmd[i]) break;
          }
          return acc.slice(0, i);
        }, matches[0]);
        if (shared.length > prefix.length) {
          setLine(baseLine.slice(0, replaceStart) + shared);
          return;
        }
        term?.write("\r\n" + matches.join("  ") + "\r\n");
        redrawLine();
      }

      function completeLine() {
        if (!term || busyRef.current) return;
        if (cursorRef.current !== lineRef.current.length) return;
        const line = lineRef.current;
        const lower = line.toLowerCase();
        const hasLongerCommand = commandsRef.current.some(
          (cmd) => cmd.startsWith(lower) && cmd !== lower,
        );
        if (hasLongerCommand) {
          if (completeCommandLine()) {
            return;
          }
        }
        if (commandsRef.current.includes(lower)) {
          setLine(lower + " ");
          void completeArgsLine();
          return;
        }
        const match = findCommandMatch(line);
        if (match && line.toLowerCase() !== match) {
          const next = match + " ";
          setLine(next);
          void completeArgsLine(next);
          return;
        }
        if (!match && line.includes(" ")) {
          if (completeCommandLine()) {
            return;
          }
          const base = line.endsWith(" ") ? line : line + " ";
          void completeArgsLine(base);
          return;
        }
        if (match && line.toLowerCase() === match) {
          setLine(match + " ");
          void completeArgsLine();
          return;
        }
        if (match && line.toLowerCase().startsWith(match + " ")) {
          void completeArgsLine();
          return;
        }
        if (!completeCommandLine()) {
          void completeArgsLine();
        }
      }

      async function showHelp() {
        if (!term) return;
        const line = lineRef.current;
        const trimmed = line.trim();
        if (!trimmed) {
          if (commandsRef.current.length === 0) {
            const cmds = await api.listCLICommands();
            if (cmds && cmds.length) {
              commandsRef.current = cmds.map((cmd) => cmd.toLowerCase());
            }
          }
          if (commandsRef.current.length > 0) {
            term.write("\r\nCommands: " + commandsRef.current.join("  ") + "\r\n");
            redrawLine();
          }
          return;
        }
        if (!line.includes(" ")) {
          const matches = commandsRef.current.filter((cmd) => cmd.startsWith(trimmed.toLowerCase()));
          if (matches.length > 0) {
            term.write("\r\nCommands: " + matches.join("  ") + "\r\n");
            redrawLine();
            return;
          }
        }
        const base = line.endsWith(" ") ? line : line + " ";
        const hints = await api.completeCLI(base);
        if (hints && hints.length > 0) {
          term.write("\r\nNext: " + hints.join("  ") + "\r\n");
          redrawLine();
          return;
        }
        term.write("\r\nNo hints available.\r\n");
        redrawLine();
      }

      term.onKey(({ key, domEvent }) => {
        if (busyRef.current || !term) return;
        const ev = domEvent;
        if (ev.key === "Tab") {
          ev.preventDefault();
          const run = async () => {
            if (!commandsRef.current.length) {
              const cmds = await api.listCLICommands();
              if (cmds && cmds.length) {
                commandsRef.current = cmds.map((cmd) => cmd.toLowerCase());
              }
            }
            completeLine();
          };
          void run();
          return;
        }
        if (key === "?" && !ev.ctrlKey && !ev.metaKey && !ev.altKey) {
          ev.preventDefault();
          void showHelp();
          return;
        }
        if (ev.key === "Enter") {
          const line = lineRef.current;
          term.write("\r\n");
          histPosRef.current = -1;
          if (!line.trim()) {
            writePrompt();
            return;
          }
          if (line === "clear" || line === "cls") {
            term.clear();
            lineRef.current = "";
            cursorRef.current = 0;
            writePrompt();
            return;
          }
          const history = historyRef.current;
          history.unshift(line);
          historyRef.current = history.slice(0, 50);
          if (persistHistoryRef.current && typeof window !== "undefined") {
            try {
              localStorage.setItem("containd.cli.history", JSON.stringify(historyRef.current));
            } catch {}
          }
          lineRef.current = "";
          cursorRef.current = 0;
          sendLine(line);
          return;
        }
        if (ev.key === "Backspace") {
          if (cursorRef.current > 0) {
            const line = lineRef.current;
            lineRef.current = line.slice(0, cursorRef.current - 1) + line.slice(cursorRef.current);
            cursorRef.current -= 1;
            redrawLine();
          }
          return;
        }
        if (ev.key === "Delete") {
          if (cursorRef.current < lineRef.current.length) {
            const line = lineRef.current;
            lineRef.current = line.slice(0, cursorRef.current) + line.slice(cursorRef.current + 1);
            redrawLine();
          }
          return;
        }
        if (ev.key === "ArrowUp") {
          ev.preventDefault();
          const next = Math.min(histPosRef.current + 1, historyRef.current.length - 1);
          if (next >= 0) {
            histPosRef.current = next;
            setLine(historyRef.current[next]);
          }
          return;
        }
        if (ev.key === "ArrowDown") {
          ev.preventDefault();
          const next = histPosRef.current - 1;
          if (next < 0) {
            histPosRef.current = -1;
            setLine("");
          } else {
            histPosRef.current = next;
            setLine(historyRef.current[next] ?? "");
          }
          return;
        }
        if (ev.key === "ArrowLeft") {
          ev.preventDefault();
          if (cursorRef.current > 0) {
            cursorRef.current -= 1;
            redrawLine();
          }
          return;
        }
        if (ev.key === "ArrowRight") {
          ev.preventDefault();
          if (cursorRef.current < lineRef.current.length) {
            cursorRef.current += 1;
            redrawLine();
          }
          return;
        }
        if (ev.key === "Home") {
          ev.preventDefault();
          cursorRef.current = 0;
          redrawLine();
          return;
        }
        if (ev.key === "End") {
          ev.preventDefault();
          cursorRef.current = lineRef.current.length;
          redrawLine();
          return;
        }
        if (ev.ctrlKey || ev.metaKey || ev.altKey) return;
        if (key.length === 1) {
          const line = lineRef.current;
          lineRef.current = line.slice(0, cursorRef.current) + key + line.slice(cursorRef.current);
          cursorRef.current += 1;
          redrawLine();
        }
      });

      const onResize = () => fitAddon?.fit();
      window.addEventListener("resize", onResize);
      resizeHandlerRef.current = onResize;
    }

    void initTerminal();

    return () => {
      disposed = true;
      if (resizeHandlerRef.current) {
        window.removeEventListener("resize", resizeHandlerRef.current);
        resizeHandlerRef.current = null;
      }
      term?.dispose();
      setTermReady(false);
    };
  }, [prompt]);

  useEffect(() => {
    if (!wsURL) return;
    if (!termReady) return;
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
  }, [prompt, termReady, wsURL]);

  useEffect(() => {
    let alive = true;
    api
      .listCLICommands()
      .then((cmds) => {
        if (!alive || !cmds) return;
        commandsRef.current = cmds.map((cmd) => cmd.toLowerCase());
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  useEffect(() => {
    const refreshPrefs = () => {
      persistHistoryRef.current = getPersistCLIHistory();
    };
    refreshPrefs();
    window.addEventListener("containd:prefs", refreshPrefs);
    return () => {
      window.removeEventListener("containd:prefs", refreshPrefs);
    };
  }, []);

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
