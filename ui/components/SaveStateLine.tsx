import type { SaveState } from "../hooks/useSaveAction";

/** The save state under a settings form; `saved` names what a save did. */
export function SaveStateLine({ state, saved, className = "mt-3" }: { state: SaveState; saved: string; className?: string }) {
  return (
    <p role="status" aria-label="Save state" className={`${className} text-xs text-(--text-muted)`}>
      State:{" "}
      {state === "saving" ? "saving…" : state === "saved" ? saved : state === "error" ? "error" : "idle"}
    </p>
  );
}
