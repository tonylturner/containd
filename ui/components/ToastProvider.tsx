"use client";

import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";

type Toast = { id: number; message: string; tone: "info" | "success" | "error" };

type ToastContextValue = {
  addToast: (message: string, tone?: Toast["tone"]) => void;
};

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const timersRef = useRef<Set<ReturnType<typeof setTimeout>>>(new Set());
  const nextId = useRef(0);

  // Clean up all pending timers on unmount
  useEffect(() => {
    const timers = timersRef.current;
    return () => {
      timers.forEach((t) => clearTimeout(t));
      timers.clear();
    };
  }, []);

  const addToast = useCallback((message: string, tone: Toast["tone"] = "info") => {
    const toast = { id: ++nextId.current, message, tone };
    setToasts((prev) => {
      const next = [...prev, toast];
      return next.slice(-4);
    });
    const timer = setTimeout(() => {
      timersRef.current.delete(timer);
      setToasts((prev) => prev.slice(1));
    }, 4000);
    timersRef.current.add(timer);
  }, []);

  const ctx = useMemo(() => ({ addToast }), [addToast]);

  const toneClasses = {
    success: "border-(--border) bg-(--green-dim) text-(--green)",
    error: "border-(--border) bg-(--red-dim) text-(--red)",
    info: "bg-(--surface) text-(--text)",
  };

  return (
    <ToastContext.Provider value={ctx}>
      {children}
      <div className="fixed bottom-4 right-4 z-50 flex w-80 flex-col gap-2" role="status" aria-live="polite" aria-label="Notifications">
        {toasts.map((t) => (
          <div
            key={t.id}
            role="alert"
            className={`card-industrial rounded-xs border px-3 py-2.5 font-mono text-xs shadow-card-lg animate-slide-down ${toneClasses[t.tone]}`}
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
