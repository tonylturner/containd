/** TAG rule labels of a connection or flow, or a dash when it has none. */
export function TagList({ tags }: { tags?: string[] }) {
  if (!tags?.length) return <>{"—"}</>;
  return (
    <div className="flex flex-wrap gap-1">
      {tags.map((t) => (
        <span key={t} className="rounded-xs bg-[rgba(6,182,212,0.15)] px-1.5 py-0.5 font-mono text-[11px] text-(--cyan)">{t}</span>
      ))}
    </div>
  );
}
