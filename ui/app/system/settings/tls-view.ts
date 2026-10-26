import type { ApiResult, TLSCertUpload, TLSInfo } from "../../../lib/api";

export type TLSRow = { label: string; value: string };

/**
 * The Management HTTPS readout: what the bound listeners serve now, plus a
 * "(next start)" row wherever the next management start serves something
 * else. `note` says why the certificate files differ. The API cleans file
 * paths, so equal strings name the same file.
 */
export type TLSView = { rows: TLSRow[]; note?: string };

const noListener = "no HTTPS listener bound";

/** Formats an RFC 3339 time for display; the raw value when unreadable. */
export function formatTLSTime(value: string | undefined): string {
  if (!value) return "—";
  const at = new Date(value);
  return Number.isNaN(at.getTime()) ? value : at.toLocaleString();
}

function listenerRows(label: string, bound: string | undefined, enabled: boolean, addr: string | undefined): TLSRow[] {
  const now = bound || "";
  const next = enabled ? addr || "" : "";
  const rows = [{ label, value: now || "not bound" }];
  if (now !== next) rows.push({ label: `${label} (next start)`, value: next || "disabled" });
  return rows;
}

export function tlsView(info: TLSInfo | null, formatTime = formatTLSTime): TLSView {
  if (!info) {
    return { rows: ["HTTP listen", "HTTPS listen", "Cert file", "Key file", "Cert expires"].map((label) => ({ label, value: "—" })) };
  }
  const rows = [
    ...listenerRows("HTTP listen", info.boundHttpListenAddr, info.httpEnabled, info.httpListenAddr),
    ...listenerRows("HTTPS listen", info.boundHttpsListenAddr, info.httpsEnabled, info.httpsListenAddr),
  ];
  const bound = Boolean(info.servedCertFile);
  if (bound) {
    rows.push(
      { label: "Cert file", value: info.servedCertFile || "—" },
      { label: "Key file", value: info.servedKeyFile || "—" },
      { label: "Cert subject", value: info.servedCertSubject || "—" },
      { label: "Cert expires", value: formatTime(info.servedCertNotAfter) },
    );
  } else {
    rows.push({ label: "Cert file", value: noListener }, { label: "Key file", value: noListener });
  }
  // Saved files matter only when the next start binds HTTPS.
  let note: string | undefined;
  if (info.httpsEnabled && !bound) {
    note = "No HTTPS listener is bound; the saved files are served from the next management start.";
  } else if (info.httpsEnabled && (info.servedCertFile !== info.certFile || info.servedKeyFile !== info.keyFile)) {
    note = "The saved files differ from the served ones; they are served from the next management start.";
  }
  if (note) {
    rows.push(
      { label: "Cert file (next start)", value: info.certFile || "—" },
      { label: "Key file (next start)", value: info.keyFile || "—" },
      { label: "Cert subject (next start)", value: info.certSubject || "—" },
      { label: "Cert expires (next start)", value: formatTime(info.certNotAfter) },
    );
  }
  return note ? { rows, note } : { rows };
}

export type Notice = { kind: "error" | "warning" | "status"; text: string };

/**
 * The page notice for a certificate upload. Status "stored" wrote the
 * files without the listener serving them yet; a refused upload, such as a
 * 409 for replacing only one of the served files, shows the server's
 * message.
 */
export function certUploadNotice(res: ApiResult<TLSCertUpload>): Notice {
  if (!res.ok) return { kind: "error", text: res.error || "Failed to upload certificate." };
  const warnings = res.data?.warnings?.filter((w) => w.trim() !== "") ?? [];
  const warning = warnings.length > 0 ? warnings.join("; ") : res.warning;
  if (res.data?.status === "stored") {
    return { kind: "warning", text: `Certificate stored but not served yet${warning ? `: ${warning}` : "."}` };
  }
  if (warning) return { kind: "warning", text: `Certificate updated with warning: ${warning}` };
  return { kind: "status", text: "Certificate updated. New connections will use it immediately." };
}
