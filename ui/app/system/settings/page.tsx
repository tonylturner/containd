"use client";

import { useCallback, useState, useSyncExternalStore } from "react";

import { useAsyncRefresh } from "../../../hooks/useAsyncRefresh";
import { Shell } from "../../../components/Shell";
import { Card } from "../../../components/Card";
import { api, isAdmin, type TLSInfo } from "../../../lib/api";
import {
  clearDismissedTips,
  getPersistCLIHistory,
  getShowTips,
  setPersistCLIHistory,
  setShowTips,
  subscribePrefs,
} from "../../../lib/prefs";
import { ManagementAccess } from "./management-access";
import { ConfirmDialog, useConfirm } from "../../../components/ConfirmDialog";
import { certUploadNotice, tlsView } from "./tls-view";

export default function SystemSettingsPage() {
  const canEdit = isAdmin();
  const confirm = useConfirm();
  const [tlsInfo, setTLSInfo] = useState<TLSInfo | null>(null);
  const [certFile, setCertFile] = useState<File | null>(null);
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [caFile, setCAFile] = useState<File | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [trustDetails, setTrustDetails] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);
  const showTips = useSyncExternalStore(subscribePrefs, getShowTips, () => true);
  const persistHistory = useSyncExternalStore(subscribePrefs, getPersistCLIHistory, () => false);

  const { refresh } = useAsyncRefresh(useCallback(async () => {
    const info = await api.getTLSInfo();
    setTLSInfo(info);
    if (!info?.managed) {
      setCertFile(null);
      setKeyFile(null);
    }
  }, []));

  const view = tlsView(tlsInfo);

  async function readFileText(f: File): Promise<string> {
    return await f.text();
  }

  async function uploadCert() {
    if (!canEdit || !tlsInfo?.managed) return;
    setError(null);
    setWarning(null);
    setStatus(null);
    if (!certFile || !keyFile) {
      setError("Select both certificate and private key PEM files.");
      return;
    }
    const [certPEM, keyPEM] = await Promise.all([readFileText(certFile), readFileText(keyFile)]);
    const res = await api.setTLSCert(certPEM, keyPEM);
    const notice = certUploadNotice(res);
    if (notice.kind === "error") {
      setError(notice.text);
      return;
    }
    if (notice.kind === "warning") setWarning(notice.text);
    else setStatus(notice.text);
    await refresh();
  }

  async function uploadCA(clear = false) {
    if (!canEdit) return;
    setError(null);
    setWarning(null);
    setStatus(null);
    setTrustDetails(null);
    if (!clear && !caFile) {
      setError("Select a PEM bundle file.");
      return;
    }
    const res = await api.setTrustedCA(clear ? { clear: true } : await readFileText(caFile!));
    if (res.state === "failed") {
      setError(res.error || "Failed to upload trusted CA bundle.");
    } else if (res.state === "stored") {
      const reason = res.warnings.length > 0 ? `: ${res.warnings.join("; ")}` : "";
      setWarning(`Trust certificates saved but not active. Applying configuration retries activation${reason || "."}`);
      setTrustDetails(`Revision: ${res.revision}${reason}`);
    } else {
      setStatus(clear ? "Additional trust cleared. Outbound TLS now uses the OS trust store." : "Trust certificates are active.");
      setTrustDetails(`Revision: ${res.revision}`);
    }
  }

  return (
    <Shell title="System Settings">
      <ConfirmDialog {...confirm.props} />
      {!canEdit && (
        <div className="mb-4 rounded-xs border bg-(--surface) px-4 py-3 text-sm text-(--text)">
          View-only mode: admin access required to change system settings.
        </div>
      )}
      {error && (
        <div className="mb-4 rounded-xs border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}
      {warning && (
        <div role="status" className="mb-4 rounded-xs border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
          {warning}
        </div>
      )}
      {status && (
        <div className="mb-4 rounded-xs border bg-(--surface) px-3 py-2 text-sm text-(--text)">
          {status}
        </div>
      )}

      {trustDetails && <details className="mb-4 rounded-xs border p-3 text-sm">
        <summary className="cursor-pointer">Trust update details</summary>
        <p className="mt-2 break-all">{trustDetails}</p>
      </details>}

      <div className="grid gap-4 md:grid-cols-2">
        <Card padding="lg">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-(--text)">Management HTTPS</h2>
            <button
              onClick={refresh}
              className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
            >
              Refresh
            </button>
          </div>

          {view.reloadError && (
            <div role="alert" aria-label="Certificate reload failed" className="mt-4 break-words rounded-xs border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
              {view.reloadError}
            </div>
          )}

          <div className="mt-4 space-y-1 text-sm">
            {view.rows.filter((row) => row.label.startsWith("HTTP")).map((row) => (
              <Row key={row.label} label={row.label} value={row.value} />
            ))}
            <details className="rounded-xs border p-3">
              <summary className="cursor-pointer">Certificate details</summary>
              {view.rows.filter((row) => !row.label.startsWith("HTTP")).map((row) => (
                <Row key={row.label} label={row.label} value={row.value} />
              ))}
            </details>
            {view.note && <p className="pt-1 text-xs text-amber">{view.note}</p>}
          </div>

          {tlsInfo && !tlsInfo.managed && (
            <div role="note" aria-label="External identity (read-only)" className="mt-5 rounded-xs border bg-(--surface) px-4 py-3 text-sm text-(--text)">
              <p className="font-semibold">External identity (read-only)</p>
              <p className="mt-1">
                This identity comes from external files that containd does not rewrite.
                Rotate them at their source; containd reloads them on change.
              </p>
            </div>
          )}

          {tlsInfo?.managed && (
            <div className="mt-5 grid gap-2">
              <label className="text-xs uppercase tracking-wide text-(--text-muted)">Certificate (PEM)</label>
              <input
                type="file"
                accept=".pem,.crt,.cer"
                disabled={!canEdit}
                onChange={(e) => setCertFile(e.target.files?.[0] ?? null)}
                className="rounded-xs border bg-(--surface) px-3 py-2 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
              />
              <label className="mt-2 text-xs uppercase tracking-wide text-(--text-muted)">Private key (PEM)</label>
              <input
                type="file"
                accept=".pem,.key"
                disabled={!canEdit}
                onChange={(e) => setKeyFile(e.target.files?.[0] ?? null)}
                className="rounded-xs border bg-(--surface) px-3 py-2 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
              />
              <button
                onClick={uploadCert}
                disabled={!canEdit}
                className="mt-2 rounded-xs bg-(--amber) px-3 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-60"
              >
                Upload cert/key
              </button>
              <p className="text-xs text-(--text-muted)">
                Self-signed is generated by default. Upload a CA-signed certificate to remove browser warnings.
              </p>
            </div>
          )}
        </Card>

        <Card padding="lg">
          <h2 className="text-lg font-semibold text-(--text)">Trusted CAs (outbound)</h2>
          <p className="mt-1 text-sm text-(--text)">
            By default, containd uses the OS trust store. You can optionally provide an additional PEM bundle for outbound TLS.
          </p>
          <div className="mt-4 grid gap-2">
            <label className="text-xs uppercase tracking-wide text-(--text-muted)">Additional CA bundle (PEM)</label>
            <input
              type="file"
              accept=".pem,.crt,.cer"
              disabled={!canEdit}
              onChange={(e) => setCAFile(e.target.files?.[0] ?? null)}
              className="rounded-xs border bg-(--surface) px-3 py-2 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
            />
            <button
              onClick={() => uploadCA()}
              disabled={!canEdit}
              className="mt-2 rounded-xs border bg-(--surface2) px-3 py-2 text-sm text-(--text) transition-ui disabled:opacity-60"
            >
              Upload CA bundle
            </button>
            <button disabled={!canEdit} className="rounded-xs border px-3 py-2 text-sm disabled:opacity-60"
              onClick={() => confirm.open({
                title: "Clear trusted CAs",
                message: "This immediately removes all additional trusted CAs. Outbound TLS to private ICAP servers or definition sources may fail. The OS trust store remains in use. This is not a staged configuration edit.",
                confirmLabel: "Clear", variant: "warning", onConfirm: () => { void uploadCA(true); },
              })}>Clear</button>
          </div>
        </Card>
      </div>

      <Card className="mt-4" padding="lg">
        <h2 className="text-lg font-semibold text-(--text)">User Preferences</h2>
        <div className="mt-4 grid gap-4 text-sm text-(--text) md:grid-cols-2">
          <label className="flex items-center justify-between gap-3 rounded-xs border bg-(--surface) px-3 py-2">
            <span>Show contextual tips</span>
            <input
              type="checkbox"
              checked={showTips}
              onChange={(e) => {
                const next = e.target.checked;
                setShowTips(next);
              }}
              className="h-4 w-4"
            />
          </label>
          <label className="flex items-center justify-between gap-3 rounded-xs border bg-(--surface) px-3 py-2">
            <span>Persist CLI history</span>
            <input
              type="checkbox"
              checked={persistHistory}
              onChange={(e) => {
                const next = e.target.checked;
                setPersistCLIHistory(next);
              }}
              className="h-4 w-4"
            />
          </label>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-(--text-muted)">
          <button
            onClick={() => {
              clearDismissedTips();
            }}
            className="rounded-md border bg-(--surface2) px-2 py-1 text-(--text) transition-ui"
          >
            Reset dismissed tips
          </button>
          <span>Preferences are stored in your browser.</span>
        </div>
      </Card>

      <ManagementAccess canEdit={canEdit} />
    </Shell>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <span className="text-(--text)">{label}</span>
      <span className="truncate text-(--text)" title={value}>{value}</span>
    </div>
  );
}
