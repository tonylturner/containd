"use client";

import * as React from "react";

type ConfirmDialogProps = {
  open: boolean;
  title: string;
  message: React.ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: "danger" | "warning" | "default";
  onConfirm: () => void;
  onCancel: () => void;
};

export function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  variant = "default",
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const confirmRef = React.useRef<HTMLButtonElement>(null);

  React.useEffect(() => {
    if (open) {
      setTimeout(() => confirmRef.current?.focus(), 50);
    }
  }, [open]);

  React.useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onCancel]);

  if (!open) return null;

  const confirmClass =
    variant === "danger"
      ? "rounded-xs bg-(--red) px-4 py-2 font-mono text-xs tracking-wider uppercase text-white hover:brightness-110 focus-visible:shadow-focus-ring outline-hidden transition-ui"
      : variant === "warning"
        ? "rounded-xs bg-(--amber) px-4 py-2 font-mono text-xs tracking-wider uppercase text-black hover:brightness-110 focus-visible:shadow-focus-ring outline-hidden transition-ui"
        : "rounded-xs bg-(--amber) px-4 py-2 font-mono text-xs tracking-wider uppercase text-black hover:brightness-110 focus-visible:shadow-focus-ring outline-hidden transition-ui";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 animate-fade-in" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
      <div className="card-industrial w-full max-w-md rounded-xs border bg-(--surface) p-6 shadow-card-lg animate-slide-down">
        <h2 id="confirm-title" className="font-display text-sm font-bold tracking-wider uppercase text-(--amber)">{title}</h2>
        <div className="mt-2 text-sm text-(--text)">{message}</div>
        <div className="mt-5 flex items-center justify-end gap-3">
          <button
            type="button"
            onClick={onCancel}
            className="rounded-xs border bg-(--surface2) px-4 py-2 font-mono text-xs tracking-wider uppercase text-(--text-dim) hover:text-(--text) focus-visible:shadow-focus-ring outline-hidden transition-ui"
          >
            {cancelLabel}
          </button>
          <button
            ref={confirmRef}
            type="button"
            onClick={onConfirm}
            className={confirmClass}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

/**
 * Hook for managing confirm dialog state.
 */
export function useConfirm() {
  const [state, setState] = React.useState<{
    open: boolean;
    title: string;
    message: React.ReactNode;
    confirmLabel?: string;
    cancelLabel?: string;
    variant?: "danger" | "warning" | "default";
    onConfirm: () => void;
  }>({
    open: false,
    title: "",
    message: "",
    onConfirm: () => {},
  });

  const open = React.useCallback(
    (opts: {
      title: string;
      message: React.ReactNode;
      confirmLabel?: string;
      cancelLabel?: string;
      variant?: "danger" | "warning" | "default";
      onConfirm: () => void;
    }) => {
      setState({ open: true, ...opts });
    },
    [],
  );

  const close = React.useCallback(() => {
    setState((prev) => ({ ...prev, open: false }));
  }, []);

  return {
    open,
    props: {
      open: state.open,
      title: state.title,
      message: state.message,
      confirmLabel: state.confirmLabel,
      cancelLabel: state.cancelLabel,
      variant: state.variant,
      onConfirm: () => {
        state.onConfirm();
        close();
      },
      onCancel: close,
    } satisfies ConfirmDialogProps,
  };
}
