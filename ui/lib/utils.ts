export function formatTimestamp(ts: string | Date): string {
  const d = typeof ts === "string" ? new Date(ts) : ts;
  return d.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

/** Binary-unit size, whole numbers from 10 up: "512 B", "1.5 KB", "12 MB"; "-" when not a number. */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes)) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

/**
 * A failure message with when to retry, from the server's Retry-After in
 * seconds: "… Try again after 10:42:15." The message alone without one.
 */
export function withRetryTime(error: string, retryAfter: number | undefined, now = Date.now()): string {
  if (retryAfter === undefined) return error;
  const at = new Date(now + retryAfter * 1000);
  return `${error} Try again after ${at.toLocaleTimeString()}.`;
}
