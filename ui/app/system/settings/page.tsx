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
import { certUploadNotice, tlsView } from "./tls-view";

export default function SystemSettingsPage() {
  const canEdit = isAdmin();
  const [tlsInfo, setTLSInfo] = useState<TLSInfo | null>(null);
  const [certFile, setCertFile] = useState<File | null>(null);
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [caFile, setCAFile] = useState<File | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
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

  async function uploadCA() {
    if (!canEdit) return;
    setError(null);
    setWarning(null);
    setStatus(null);
    if (!caFile) {
      setError("Select a PEM bundle file.");
      return;
    }
    const pem = await readFileText(caFile);
    const res = await api.setTrustedCA(pem);
    if (res.state === "failed") {
      setError(res.error || "Failed to upload trusted CA bundle.");
    } else if (res.state === "stored") {
      const reason = res.warnings.length > 0 ? `: ${res.warnings.join("; ")}` : "";
      setWarning(`Trusted CA bundle stored (revision ${res.revision}), but the engine did not apply it${reason}. The next commit retries it.`);
    } else {
      setStatus(`Trusted CA bundle applied by the engine (revision ${res.revision}).`);
    }
  }

  return (
    <Shell title="System Settings">
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
            {view.rows.map((row) => (
              <Row key={row.label} label={row.label} value={row.value} />
            ))}
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
              onClick={uploadCA}
              disabled={!canEdit}
              className="mt-2 rounded-xs border bg-(--surface2) px-3 py-2 text-sm text-(--text) transition-ui disabled:opacity-60"
            >
              Upload CA bundle
            </button>
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

      <Card className="mt-4" padding="lg">
        <p className="text-sm text-(--text)">
          CLI shortcuts:
        </p>
        <pre className="mt-3 rounded-xs bg-(--surface) p-3 text-xs text-(--text)">
show system{"\n"}
set system mgmt listen &lt;addr&gt;{"\n"}
set system mgmt http enable &lt;true|false&gt;{"\n"}
set system mgmt https enable &lt;true|false&gt;{"\n"}
set system mgmt redirect-http-to-https &lt;true|false&gt;{"\n"}
set system mgmt hsts &lt;true|false&gt; [max_age_seconds]{"\n"}
set system ssh allow-password &lt;true|false&gt;{"\n"}
commit
        </pre>
      </Card>
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
