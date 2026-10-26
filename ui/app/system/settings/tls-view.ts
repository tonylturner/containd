import type { ApiResult, TLSCertUpload, TLSInfo } from "../../../lib/api";

/**
 * The management certificate files: the ones the bound HTTPS listener
 * serves now and the saved ones it serves from the next start. `pending`
 * is set when the next start serves files other than the served ones,
 * with `pendingNote` saying why.
 */
export type TLSFilesView = {
  servedCert: string;
  servedKey: string;
  savedCert: string;
  savedKey: string;
  pending: boolean;
  pendingNote?: string;
};

const noListener = "no HTTPS listener bound";

export function tlsFilesView(info: TLSInfo | null): TLSFilesView {
  if (!info) {
    return { servedCert: "—", servedKey: "—", savedCert: "—", savedKey: "—", pending: false };
  }
  const bound = Boolean(info.servedCertFile || info.servedKeyFile);
  const view: TLSFilesView = {
    servedCert: bound ? info.servedCertFile || "—" : noListener,
    servedKey: bound ? info.servedKeyFile || "—" : noListener,
    savedCert: info.certFile || "—",
    savedKey: info.keyFile || "—",
    pending: false,
  };
  // Saved files matter only when the next start binds HTTPS.
  if (!info.httpsEnabled) return view;
  if (!bound) {
    return { ...view, pending: true, pendingNote: "No HTTPS listener is bound; the saved files are served from the next management start." };
  }
  if (info.servedCertFile !== info.certFile || info.servedKeyFile !== info.keyFile) {
    return { ...view, pending: true, pendingNote: "The saved files differ from the served ones; they are served from the next management start." };
  }
  return view;
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
