"use client";

import { useCallback, useState } from "react";
import Link from "next/link";
import { Card } from "../../../components/Card";
import { api, type ConfigBundle } from "../../../lib/api";
import { ConfigEditNotice, useConfigEditor } from "../../../lib/use-config-editor";
import { useAsyncRefresh } from "../../../hooks/useAsyncRefresh";
import { useConfigRefresh } from "../../../lib/use-config-refresh";

type Group = "mgmt" | "ssh";
const mgmtText = [
  ["httpListenAddr", "HTTP listen address"],
  ["httpsListenAddr", "HTTPS listen address"],
  ["tlsCertFile", "TLS certificate path"],
  ["tlsKeyFile", "TLS private key path"],
  ["trustedCAFile", "Trusted CA path"],
] as const;
const sshText = [
  ["listenAddr", "SSH listen address"],
  ["authorizedKeysDir", "Authorized keys directory"],
  ["banner", "SSH banner"],
] as const;

export function ManagementAccess({ canEdit }: { canEdit: boolean }) {
  const draft = useConfigEditor<ConfigBundle | null>(null, false);
  const { readConfig } = draft;
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const { refresh } = useAsyncRefresh(useCallback(async () => {
    readConfig(await api.getCandidateConfig());
  }, [readConfig]));
  useConfigRefresh(refresh);
  const system = draft.cfg?.system ?? {};

  function update(group: Group | null, key: string, value: string | boolean | number | undefined) {
    draft.setCfg(cfg => {
      if (!cfg) return cfg;
      const next = { ...cfg.system };
      if (group) next[group] = { ...next[group], [key]: value };
      else next.hostname = value as string;
      // The modern HTTP field replaces, rather than competes with, the alias.
      if (group === "mgmt" && key === "httpListenAddr") next.mgmt!.listenAddr = "";
      return { ...cfg, system: next };
    });
    setStatus(null);
    setError(null);
  }

  async function save() {
    if (!canEdit || !draft.cfg || saving) return;
    setSaving(true);
    setError(null);
    setStatus(null);
    const submitted = draft.cfg;
    // The server owns reservation and enrolled-admin-key lockout checks.
    // Staging validates again atomically with the revision precondition.
    const result = await draft.write(async base => {
      const valid = await api.validateConfig(submitted);
      return valid.ok ? api.setCandidateConfig(base, submitted) : valid;
    }, { replace: () => submitted });
    setSaving(false);
    if (!result.ok) { setError(result.error); return; }
    setStatus(`Management access staged — review and use Commit-confirmed.${result.warning ? ` Warning: ${result.warning}` : ""}`);
    await refresh();
  }

  function text(group: Group, key: string): string {
    const values = system[group] as Record<string, unknown> | undefined;
    return String(values?.[key] ?? (group === "mgmt" && key === "httpListenAddr" ? system.mgmt?.listenAddr ?? "" : ""));
  }
  function input(group: Group, key: string, label: string, numeric?: { max?: number }) {
    return <label key={key} className="grid min-w-0 gap-1 text-sm">
      {label}
      <input className="w-full min-w-0 input-industrial" value={text(group, key)}
        type={numeric ? "number" : "text"} min={numeric ? 0 : undefined} max={numeric?.max}
        onChange={e => update(group, key, numeric ? (e.target.value === "" ? undefined : Number(e.target.value)) : e.target.value)} />
    </label>;
  }
  function toggle(group: Group, key: string, label: string) {
    const value = (system[group] as Record<string, unknown> | undefined)?.[key];
    return <label key={key} className="grid min-w-0 gap-1 text-sm">
      {label}
      <select className="w-full input-industrial" value={value === undefined ? "" : String(value)}
        onChange={e => update(group, key, e.target.value === "" ? undefined : e.target.value === "true")}>
        <option value="">Default (not explicitly set)</option>
        <option value="true">Enabled</option>
        <option value="false">Disabled</option>
      </select>
    </label>;
  }

  return <Card className="mt-4" padding="lg">
    <h2 className="text-lg font-semibold">Advanced management access</h2>
    <p className="mt-2 text-sm">These edits stage into the candidate, not the active settings. Review and use Commit-confirmed to protect access.</p>
    <p className="mt-2 text-sm">Listener addresses and SSH shell mode require a management restart after commit. Environment overrides take precedence over saved settings. Paths refer to files inside the appliance, not your browser.</p>
    <p className="mt-2 text-sm">Disabling SSH passwords requires an enrolled administrator key accepted by the server. Reserved management paths cannot be disabled or redirected.</p>
    <ConfigEditNotice superseded={draft.editor.superseded} {...draft.conflictProps}
      onReload={async () => readConfig(await api.getCandidateConfig(), false)} />
    {!draft.available && <p role="alert" className="mt-3 text-red-400">Management configuration unavailable. Refresh before editing.</p>}
    {error && <p role="alert" className="mt-3 break-words text-red-400">{error}</p>}
    {status && <p role="status" className="mt-3">{status} <Link href="/config/?tab=diff" className="underline">Review changes</Link></p>}
    <form onSubmit={e => { e.preventDefault(); void save(); }} className="mt-4">
      <fieldset disabled={!canEdit || !draft.writable || saving} className="grid min-w-0 gap-4 disabled:opacity-60">
        <label className="grid gap-1 text-sm">Hostname
          <input className="w-full input-industrial" value={system.hostname ?? ""}
            onChange={e => update(null, "hostname", e.target.value)} />
        </label>
        <fieldset className="grid min-w-0 gap-3 md:grid-cols-2">
          <legend className="mb-2 font-semibold">HTTP / HTTPS</legend>
          {mgmtText.map(([key, label]) => input("mgmt", key, label))}
          {toggle("mgmt", "enableHTTP", "HTTP access")}
          {toggle("mgmt", "enableHTTPS", "HTTPS access")}
          {toggle("mgmt", "redirectHTTPToHTTPS", "Redirect HTTP to HTTPS")}
          {toggle("mgmt", "enableHSTS", "HSTS")}
          {input("mgmt", "hstsMaxAgeSeconds", "HSTS max age (seconds)", {})}
        </fieldset>
        <fieldset className="grid min-w-0 gap-3 md:grid-cols-2">
          <legend className="mb-2 font-semibold">SSH</legend>
          {sshText.map(([key, label]) => input("ssh", key, label))}
          {toggle("ssh", "allowPassword", "SSH password authentication")}
          {input("ssh", "hostKeyRotationDays", "Host key rotation (days; 0 disables)", { max: 36500 })}
          <label className="grid gap-1 text-sm">SSH shell mode
            <select className="w-full input-industrial" value={system.ssh?.shellMode ?? ""}
              onChange={e => update("ssh", "shellMode", e.target.value)}>
              <option value="">Default (appliance)</option>
              <option value="appliance">Appliance CLI</option>
              <option value="linux">Linux shell</option>
            </select>
          </label>
        </fieldset>
        <button className="justify-self-start rounded-xs border bg-(--surface2) px-3 py-2 text-sm" type="submit">
          {saving ? "Saving…" : "Save management access"}
        </button>
      </fieldset>
      <button type="button" onClick={refresh} className="mt-3 rounded-xs border px-3 py-2 text-sm">Refresh management access</button>
    </form>
  </Card>;
}
