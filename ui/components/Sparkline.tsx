type SparklineProps = {
  values: number[];
  color?: string;
  background?: string;
  className?: string;
  title?: string;
};

export function Sparkline({
  values,
  color = "var(--primary)",
  background = "linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.01))",
  className = "",
  title,
}: SparklineProps) {
  if (!values?.length) {
    values = [0];
  }
  const max = Math.max(...values, 1);
  return (
    <div
      title={title}
      className={`flex items-end gap-1 overflow-hidden rounded-lg border border-white/10 bg-white/5 px-2 py-2 ${className}`}
      style={{ background }}
    >
      {values.map((v, idx) => (
        <div
          key={idx}
          className="w-full rounded-sm"
          style={{
            height: `${Math.max(4, Math.round((v / max) * 100))}%`,
            background: `linear-gradient(180deg, ${color}, ${color}80)`,
          }}
        />
      ))}
    </div>
  );
}
