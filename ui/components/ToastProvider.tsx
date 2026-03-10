"use client";

import React, { createContext, useCallback, useContext, useMemo, useState } from "react";

type Toast = { id: number; message: string; tone: "info" | "success" | "error" };

type ToastContextValue = {
  addToast: (message: string, tone?: Toast["tone"]) => void;
};

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const addToast = useCallback((message: string, tone: Toast["tone"] = "info") => {
    setToasts((prev) => {
      const next = [...prev, { id: Date.now(), message, tone }];
      return next.slice(-4);
    });
    setTimeout(() => {
      setToasts((prev) => prev.slice(1));
    }, 4000);
  }, []);

  const ctx = useMemo(() => ({ addToast }), [addToast]);

  const toneClasses = {
    success: "border-[var(--green)]/25 bg-[var(--green-dim)] text-[var(--green)]",
    error: "border-[var(--red)]/25 bg-[var(--red-dim)] text-[var(--red)]",
    info: "border-amber-500/[0.15] bg-[var(--surface)] text-[var(--text)]",
  };

  return (
    <ToastContext.Provider value={ctx}>
      {children}
      <div className="fixed bottom-4 right-4 z-50 flex w-80 flex-col gap-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`card-industrial rounded-sm border px-3 py-2.5 font-mono text-xs shadow-card-lg animate-slide-down ${toneClasses[t.tone]}`}
          >
            {t.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx.addToast;
}
