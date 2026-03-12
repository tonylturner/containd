"use client";

import { useEffect, useMemo, useState } from "react";

import { Shell } from "../../../components/Shell";
import { Card } from "../../../components/Card";
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
    if (!res.ok) {
      setError(res.error || "Failed to upload certificate.");
      return;
    }
    setStatus(res.warning ? `Certificate updated with warning: ${res.warning}` : "Certificate updated. New connections will use it immediately.");
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
    if (!res.ok) {
      setError(res.error || "Failed to upload trusted CA bundle.");
      return;
    }
    setStatus(res.warning ? `Trusted CA bundle saved with warning: ${res.warning}` : "Trusted CA bundle saved.");
  }

  return (
    <Shell title="System Settings">
      {!canEdit && (
        <div className="mb-4 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3 text-sm text-[var(--text)]">
          View-only mode: admin access required to change system settings.
        </div>
      )}
      {error && (
        <div className="mb-4 rounded-sm border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}
      {status && (
        <div className="mb-4 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text)]">
          {status}
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <Card padding="lg">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-[var(--text)]">Management HTTPS</h2>
            <button
              onClick={refresh}
              className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
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
            <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">Certificate (PEM)</label>
            <input
              type="file"
              accept=".pem,.crt,.cer"
              disabled={!canEdit}
              onChange={(e) => setCertFile(e.target.files?.[0] ?? null)}
              className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
            />
            <label className="mt-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">Private key (PEM)</label>
            <input
              type="file"
              accept=".pem,.key"
              disabled={!canEdit}
              onChange={(e) => setKeyFile(e.target.files?.[0] ?? null)}
              className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
            />
            <button
              onClick={uploadCert}
              disabled={!canEdit}
              className="mt-2 rounded-sm bg-[var(--amber)] px-3 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-60"
            >
              Upload cert/key
            </button>
            <p className="text-xs text-[var(--text-muted)]">
              Self-signed is generated by default. Upload a CA-signed certificate to remove browser warnings.
            </p>
          </div>
        </Card>

        <Card padding="lg">
          <h2 className="text-lg font-semibold text-[var(--text)]">Trusted CAs (outbound)</h2>
          <p className="mt-1 text-sm text-[var(--text)]">
            By default, containd uses the OS trust store. You can optionally provide an additional PEM bundle for outbound TLS.
          </p>
          <div className="mt-4 grid gap-2">
            <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">Additional CA bundle (PEM)</label>
            <input
              type="file"
              accept=".pem,.crt,.cer"
              disabled={!canEdit}
              onChange={(e) => setCAFile(e.target.files?.[0] ?? null)}
              className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
            />
            <button
              onClick={uploadCA}
              disabled={!canEdit}
              className="mt-2 rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-2 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08] disabled:opacity-60"
            >
              Upload CA bundle
            </button>
          </div>
        </Card>
      </div>

      <Card className="mt-4" padding="lg">
        <h2 className="text-lg font-semibold text-[var(--text)]">User Preferences</h2>
        <div className="mt-4 grid gap-4 text-sm text-[var(--text)] md:grid-cols-2">
          <label className="flex items-center justify-between gap-3 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2">
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
          <label className="flex items-center justify-between gap-3 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2">
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
        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-[var(--text-muted)]">
          <button
            onClick={() => {
              clearDismissedTips();
            }}
            className="rounded-md border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
          >
            Reset dismissed tips
          </button>
          <span>Preferences are stored in your browser.</span>
        </div>
      </Card>

      <Card className="mt-4" padding="lg">
        <p className="text-sm text-[var(--text)]">
          CLI shortcuts:
        </p>
        <pre className="mt-3 rounded-sm bg-[var(--surface)] p-3 text-xs text-[var(--text)]">
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

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <span className="text-[var(--text)]">{label}</span>
      <span className="truncate text-[var(--text)]">{value}</span>
    </div>
  );
}
