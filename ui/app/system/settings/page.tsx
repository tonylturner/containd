"use client";

import { useEffect, useMemo, useState } from "react";

import { Shell } from "../../../components/Shell";
import { api, isAdmin, type TLSInfo } from "../../../lib/api";
import {
  clearDismissedTips,
  getPersistCLIHistory,
  getShowTips,
  setPersistCLIHistory,
  setShowTips,
} from "../../../lib/prefs";

export default function SystemSettingsPage() {
  const canEdit = isAdmin();
  const [tlsInfo, setTLSInfo] = useState<TLSInfo | null>(null);
  const [certFile, setCertFile] = useState<File | null>(null);
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [caFile, setCAFile] = useState<File | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showTips, setShowTipsState] = useState(true);
  const [persistHistory, setPersistHistory] = useState(false);

  async function refresh() {
    const info = await api.getTLSInfo();
    setTLSInfo(info);
  }

  useEffect(() => {
    refresh();
    setShowTipsState(getShowTips());
    setPersistHistory(getPersistCLIHistory());
  }, []);

  const certSummary = useMemo(() => {
    if (!tlsInfo?.certNotAfter) return "—";
    try {
      return new Date(tlsInfo.certNotAfter).toLocaleString();
    } catch {
      return tlsInfo.certNotAfter;
    }
  }, [tlsInfo?.certNotAfter]);

  async function readFileText(f: File): Promise<string> {
    return await f.text();
  }

  async function uploadCert() {
    if (!canEdit) return;
    setError(null);
    setStatus(null);
    if (!certFile || !keyFile) {
      setError("Select both certificate and private key PEM files.");
      return;
    }
    const [certPEM, keyPEM] = await Promise.all([readFileText(certFile), readFileText(keyFile)]);
    const res = await api.setTLSCert(certPEM, keyPEM);
    if (!res) {
      setError("Failed to upload certificate.");
      return;
    }
    setStatus("Certificate updated. New connections will use it immediately.");
    await refresh();
  }

  async function uploadCA() {
    if (!canEdit) return;
    setError(null);
    setStatus(null);
    if (!caFile) {
      setError("Select a PEM bundle file.");
      return;
    }
    const pem = await readFileText(caFile);
    const res = await api.setTrustedCA(pem);
    if (!res) {
      setError("Failed to upload trusted CA bundle.");
      return;
    }
    setStatus("Trusted CA bundle saved.");
  }

  return (
    <Shell title="System Settings">
      {!canEdit && (
        <div className="mb-4 rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-200">
          View-only mode: admin access required to change system settings.
        </div>
      )}
      {error && (
        <div className="mb-4 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
          {error}
        </div>
      )}
      {status && (
        <div className="mb-4 rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-200">
          {status}
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <div className="rounded-2xl border border-white/10 bg-white/5 p-6 shadow-lg backdrop-blur">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white">Management HTTPS</h2>
            <button
              onClick={refresh}
              className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
            >
              Refresh
            </button>
          </div>

          <div className="mt-4 space-y-1 text-sm">
            <Row label="HTTP" value={tlsInfo ? (tlsInfo.httpEnabled ? "enabled" : "disabled") : "—"} />
            <Row label="HTTP listen" value={tlsInfo?.httpListenAddr ?? "—"} />
            <Row label="HTTPS" value={tlsInfo ? (tlsInfo.httpsEnabled ? "enabled" : "disabled") : "—"} />
            <Row label="HTTPS listen" value={tlsInfo?.httpsListenAddr ?? "—"} />
            <Row label="Cert file" value={tlsInfo?.certFile ?? "—"} />
            <Row label="Key file" value={tlsInfo?.keyFile ?? "—"} />
            <Row label="Cert expires" value={certSummary} />
          </div>

          <div className="mt-5 grid gap-2">
            <label className="text-xs uppercase tracking-wide text-slate-400">Certificate (PEM)</label>
            <input
              type="file"
              accept=".pem,.crt,.cer"
              disabled={!canEdit}
              onChange={(e) => setCertFile(e.target.files?.[0] ?? null)}
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-slate-200"
            />
            <label className="mt-2 text-xs uppercase tracking-wide text-slate-400">Private key (PEM)</label>
            <input
              type="file"
              accept=".pem,.key"
              disabled={!canEdit}
              onChange={(e) => setKeyFile(e.target.files?.[0] ?? null)}
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-slate-200"
            />
            <button
              onClick={uploadCert}
              disabled={!canEdit}
              className="mt-2 rounded-lg bg-mint/20 px-3 py-2 text-sm text-mint hover:bg-mint/30 disabled:opacity-60"
            >
              Upload cert/key
            </button>
            <p className="text-xs text-slate-400">
              Self-signed is generated by default. Upload a CA-signed certificate to remove browser warnings.
            </p>
          </div>
        </div>

        <div className="rounded-2xl border border-white/10 bg-white/5 p-6 shadow-lg backdrop-blur">
          <h2 className="text-lg font-semibold text-white">Trusted CAs (outbound)</h2>
          <p className="mt-1 text-sm text-slate-200">
            By default, containd uses the OS trust store. You can optionally provide an additional PEM bundle for outbound TLS.
          </p>
          <div className="mt-4 grid gap-2">
            <label className="text-xs uppercase tracking-wide text-slate-400">Additional CA bundle (PEM)</label>
            <input
              type="file"
              accept=".pem,.crt,.cer"
              disabled={!canEdit}
              onChange={(e) => setCAFile(e.target.files?.[0] ?? null)}
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-slate-200"
            />
            <button
              onClick={uploadCA}
              disabled={!canEdit}
              className="mt-2 rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-200 hover:bg-white/10 disabled:opacity-60"
            >
              Upload CA bundle
            </button>
          </div>
        </div>
      </div>

      <div className="mt-4 rounded-2xl border border-white/10 bg-white/5 p-6 shadow-lg backdrop-blur">
        <h2 className="text-lg font-semibold text-white">User Preferences</h2>
        <div className="mt-4 grid gap-4 text-sm text-slate-200 md:grid-cols-2">
          <label className="flex items-center justify-between gap-3 rounded-lg border border-white/10 bg-black/30 px-3 py-2">
            <span>Show contextual tips</span>
            <input
              type="checkbox"
              checked={showTips}
              onChange={(e) => {
                const next = e.target.checked;
                setShowTipsState(next);
                setShowTips(next);
              }}
              className="h-4 w-4"
            />
          </label>
          <label className="flex items-center justify-between gap-3 rounded-lg border border-white/10 bg-black/30 px-3 py-2">
            <span>Persist CLI history</span>
            <input
              type="checkbox"
              checked={persistHistory}
              onChange={(e) => {
                const next = e.target.checked;
                setPersistHistory(next);
                setPersistCLIHistory(next);
              }}
              className="h-4 w-4"
            />
          </label>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-slate-400">
          <button
            onClick={() => {
              clearDismissedTips();
            }}
            className="rounded-md border border-white/10 bg-white/5 px-2 py-1 text-slate-200 hover:bg-white/10"
          >
            Reset dismissed tips
          </button>
          <span>Preferences are stored in your browser.</span>
        </div>
      </div>

      <div className="mt-4 rounded-2xl border border-white/10 bg-white/5 p-6 shadow-lg backdrop-blur">
        <p className="text-sm text-slate-200">
          CLI shortcuts:
        </p>
        <pre className="mt-3 rounded-lg bg-black/40 p-3 text-xs text-slate-200">
show system{"\n"}
set system mgmt listen &lt;addr&gt;{"\n"}
set system mgmt http enable &lt;true|false&gt;{"\n"}
set system mgmt https enable &lt;true|false&gt;{"\n"}
set system mgmt redirect-http-to-https &lt;true|false&gt;{"\n"}
set system mgmt hsts &lt;true|false&gt; [max_age_seconds]{"\n"}
set system ssh allow-password &lt;true|false&gt;{"\n"}
commit
        </pre>
      </div>
    </Shell>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <span className="text-slate-300">{label}</span>
      <span className="truncate text-slate-100">{value}</span>
    </div>
  );
}
