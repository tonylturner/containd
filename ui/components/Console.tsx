"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { api, type CLIExecuteResponse } from "../lib/api";

type Line = { kind: "prompt" | "output" | "error"; text: string };

export function Console({ prompt = "containd# " }: { prompt?: string }) {
  const [lines, setLines] = useState<Line[]>([
    { kind: "output", text: "containd in-app CLI. Type 'show version'." },
  ]);
  const [input, setInput] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const [histPos, setHistPos] = useState<number>(-1);
  const [busy, setBusy] = useState(false);
  const endRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [lines, busy]);

  const shown = useMemo(() => lines.slice(-500), [lines]);

  async function runLine(line: string) {
    const trimmed = line.trim();
    if (!trimmed) return;
    if (trimmed === "clear" || trimmed === "cls") {
      setLines([]);
      return;
    }
    setLines((prev) => [...prev, { kind: "prompt", text: prompt + trimmed }]);
    setBusy(true);
    let res: CLIExecuteResponse | null = null;
    try {
      res = await api.executeCLI(trimmed);
    } finally {
      setBusy(false);
    }
    if (!res) {
      setLines((prev) => [
        ...prev,
        { kind: "error", text: "Failed to reach management API." },
      ]);
      return;
    }
    if (res.output) {
      setLines((prev) => [
        ...prev,
        ...res.output
          .trimEnd()
          .split("\n")
          .filter(Boolean)
          .map((t) => ({ kind: "output" as const, text: t })),
      ]);
    }
    if (res.error) {
      setLines((prev) => [...prev, { kind: "error", text: res.error! }]);
    }
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter") {
      const line = input;
      setInput("");
      setHistPos(-1);
      if (line.trim()) {
        setHistory((prev) => [line.trim(), ...prev].slice(0, 50));
      }
      runLine(line);
      return;
    }
    if (e.key === "ArrowUp") {
      e.preventDefault();
      const next = Math.min(histPos + 1, history.length - 1);
      if (next >= 0) {
        setHistPos(next);
        setInput(history[next]);
      }
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      const next = histPos - 1;
      if (next < 0) {
        setHistPos(-1);
        setInput("");
      } else {
        setHistPos(next);
        setInput(history[next]);
      }
    }
  }

  return (
    <div
      className="rounded-2xl border border-white/10 bg-black/40 p-4 shadow-inner backdrop-blur"
      onClick={() => inputRef.current?.focus()}
    >
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

      <div className="h-64 overflow-y-auto rounded-lg border border-white/5 bg-black/60 px-3 py-2 font-mono text-xs text-slate-100">
        {shown.map((l, i) => (
          <div
            key={i}
            className={
              l.kind === "error"
                ? "text-amber"
                : l.kind === "prompt"
                  ? "text-slate-300"
                  : "text-slate-100"
            }
          >
            {l.text}
          </div>
        ))}
        {busy && <div className="text-slate-400">…</div>}
        <div ref={endRef} />
      </div>

      <div className="mt-2 flex items-center gap-2 font-mono text-xs">
        <span className="text-slate-300">{prompt}</span>
        <input
          ref={inputRef}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={onKeyDown}
          disabled={busy}
          className="w-full rounded-md border border-white/10 bg-black/50 px-2 py-1 text-slate-100 outline-none focus:border-white/20"
          spellCheck={false}
          autoCapitalize="none"
          autoCorrect="off"
        />
      </div>
    </div>
  );
}

