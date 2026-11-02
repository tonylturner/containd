"use client";

import { useRef, useState } from "react";

export function InfoTip({ label }: { label: string }) {
  const tooltip = useRef<HTMLSpanElement>(null);
  const [offset, setOffset] = useState(0);
  function placeTooltip(event: { currentTarget: HTMLSpanElement }) {
    const marker = event.currentTarget.getBoundingClientRect();
    const halfWidth = (tooltip.current?.getBoundingClientRect().width ?? 0) / 2;
    const center = marker.left + marker.width / 2;
    const bounded = Math.max(halfWidth + 8, Math.min(center, window.innerWidth - halfWidth - 8));
    setOffset(bounded - center);
  }
  return (
    <span onFocus={placeTooltip} onMouseEnter={placeTooltip}
      className="relative inline-flex shrink-0 items-center align-middle group">
      <span
        role="img"
        aria-label={`Info: ${label}`}
        tabIndex={0}
        className="flex size-4 shrink-0 items-center justify-center rounded-xs border bg-(--surface2) font-mono text-[10px] leading-none text-(--text-dim) transition-ui group-hover:text-(--amber) focus-visible:shadow-focus-ring outline-hidden"
      >
        i
      </span>
      <span ref={tooltip} role="tooltip" style={{ marginLeft: offset }}
        className="pointer-events-none absolute left-1/2 top-full z-20 mt-2 w-64 max-w-[calc(100vw-1rem)] -translate-x-1/2 rounded-xs border bg-(--surface) px-3 py-2 font-mono text-[11px] text-(--text) opacity-0 shadow-card-lg transition-opacity duration-150 group-hover:opacity-100 group-focus-within:opacity-100">
        {label}
      </span>
    </span>
  );
}
