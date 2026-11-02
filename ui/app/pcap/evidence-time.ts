const goZeroTime = Date.parse("0001-01-01T00:00:00Z");

export function formatEvidenceTime(value?: string | null, missing = "Unknown"): string {
  if (!value) return missing;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  if (date.getTime() === goZeroTime) return missing;
  return date.toLocaleString();
}
