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
    success: "border-emerald-500/25 bg-emerald-500/12 text-emerald-300",
    error: "border-red-500/25 bg-red-500/12 text-red-300",
    info: "border-white/[0.08] bg-surface-raised text-slate-200",
  };

  return (
    <ToastContext.Provider value={ctx}>
      {children}
      <div className="fixed bottom-4 right-4 z-50 flex w-80 flex-col gap-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`rounded-lg border px-3 py-2.5 text-sm shadow-card-lg animate-slide-down ${toneClasses[t.tone]}`}
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
