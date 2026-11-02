"use client";

import type { Dispatch, SetStateAction } from "react";
import type { ReverseProxySite } from "../../lib/api";
import { Disclosure } from "../../components/Disclosure";

const inputClass = "mt-1 w-full min-w-0 input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden";

/** Edits stay local until added to the list, then Save stages the list. */
export function ReverseSiteForm({ site, setSite, backends, setBackends, hostnames, setHostnames, editing, disabled, onAccept, onCancel }: {
  site: ReverseProxySite;
  setSite: Dispatch<SetStateAction<ReverseProxySite>>;
  backends: string;
  setBackends: (value: string) => void;
  hostnames: string;
  setHostnames: (value: string) => void;
  editing: boolean;
  disabled: boolean;
  onAccept: () => void;
  onCancel: () => void;
}) {
  return (
    <div className="min-w-0 rounded-xs border bg-(--surface) p-4">
      <h3 className="text-sm font-semibold text-(--text)">{editing ? "Edit site" : "Add site"}</h3>
      <p className="mt-1 text-xs text-(--text-muted)">
        {editing ? "Update site changes the local list." : "Add changes the local list."} Save stages it; commit applies it.
      </p>
      <div className="mt-3 grid min-w-0 gap-3 md:grid-cols-2">
        <label className="min-w-0 text-sm">
          Site name
          <input type="text" value={site.name} disabled={disabled}
            onChange={e => setSite(s => ({ ...s, name: e.target.value }))}
            placeholder="site name" className={inputClass} />
        </label>
        <label className="min-w-0 text-sm">
          Listen port
          <input type="number" min={1} max={65535} value={site.listenPort} disabled={disabled}
            onChange={e => setSite(s => ({ ...s, listenPort: Number(e.target.value) }))}
            placeholder="listen port" className={inputClass} />
        </label>
        <label className="min-w-0 text-sm md:col-span-2">
          Backends
          <input type="text" value={backends} disabled={disabled} onChange={e => setBackends(e.target.value)}
            placeholder="backends host:port, host:port" className={inputClass} />
        </label>
        <label className="min-w-0 text-sm md:col-span-2">
          Hostnames
          <input type="text" value={hostnames} disabled={disabled} onChange={e => setHostnames(e.target.value)}
            placeholder="hostnames (optional)" className={inputClass} />
        </label>
        <label className="min-w-0 text-sm md:col-span-2">
          Description
          <input type="text" value={site.description ?? ""} disabled={disabled}
            onChange={e => setSite(s => ({ ...s, description: e.target.value }))}
            className={inputClass} />
        </label>
      </div>
      <div className="mt-3">
        <Disclosure title="Site TLS" defaultOpen={!!site.tlsEnabled || !!site.certRef}
          indicator={site.tlsEnabled ? "TLS enabled" : site.certRef ? "Certificate reference saved; TLS disabled" : "TLS disabled"}>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={site.tlsEnabled ?? false} disabled={disabled}
              onChange={e => setSite(s => ({ ...s, tlsEnabled: e.target.checked }))}
              className="h-4 w-4 rounded-sm bg-(--surface)" />
            Enable TLS
          </label>
          <label className="block text-sm">
            Certificate reference
            <input type="text" value={site.certRef ?? ""} disabled={disabled} maxLength={128}
              onChange={e => setSite(s => ({ ...s, certRef: e.target.value }))}
              aria-describedby="proxy-certificate-help" placeholder="plant-web" className={inputClass} />
          </label>
          <p id="proxy-certificate-help" className="text-xs text-(--text-muted)">
            Provision a matching, currently valid PEM certificate and private key on the management service host:
            {" "}<code>&lt;reference&gt;.crt</code> and <code>&lt;reference&gt;.key</code> in <code>/data/certs</code>
            {" "}(or <code>CONTAIND_CERTS_DIR</code>). The reference is a filename stem, not a path:
            1–128 ASCII letters, digits, underscores or hyphens, starting with a letter or digit.
            There is no proxy certificate upload here. System Settings uploads the management HTTPS identity, not proxy certificates.
          </p>
        </Disclosure>
      </div>
      <div className="mt-3 flex flex-wrap justify-end gap-2">
        {editing && <button type="button" onClick={onCancel}
          className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm transition-ui">Cancel edit</button>}
        <button type="button" disabled={disabled} onClick={onAccept}
          className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm transition-ui disabled:opacity-50">
          {editing ? "Update site" : "Add"}
        </button>
      </div>
    </div>
  );
}
