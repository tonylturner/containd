"use client";

import { useEffect, useState } from "react";
import { generateWireGuardKeyPair } from "./wireguard-keys";

const button = "rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm transition-ui disabled:opacity-50";

export function WireGuardKeyEditor({ value, configured, disabled, onChange }: {
  value: string; configured: boolean; disabled: boolean;
  onChange: (privateKey: string, publicKey?: string) => void;
}) {
  const [supported, setSupported] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [replacing, setReplacing] = useState(false);
  useEffect(() => {
    let active = true;
    // Probe the actual operation: SubtleCrypto alone does not imply X25519.
    generateWireGuardKeyPair().then(() => { if (active) setSupported(true); })
      .catch(() => { if (active) setSupported(false); });
    return () => { active = false; };
  }, []);
  async function generate() {
    setBusy(true);
    setError(null);
    try {
      const pair = await generateWireGuardKeyPair();
      onChange(pair.privateKey, pair.publicKey);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Key generation failed.");
    } finally { setBusy(false); }
  }
  return <section aria-label="WireGuard private key" className="grid gap-2">
    {configured && <div className="flex flex-wrap items-center gap-2 text-sm">
      <span>Private key configured</span><span aria-hidden="true">—</span>
      <button className={button} disabled={disabled || busy} onClick={() => setReplacing(true)}>Replace</button>
    </div>}
    {(!configured || replacing || value) && <label className="grid gap-1 text-xs">
      Private Key (base64)
      <input type="password" autoComplete="new-password" value={value} disabled={disabled || busy}
        onChange={e => onChange(e.target.value)}
        className="w-full min-w-0 input-industrial" placeholder={configured ? "Leave blank to keep the stored key" : "Server private key"} />
    </label>}
    {value && <p className="text-xs text-(--text-muted)">New private key ready to stage. Save stages it; commit applies it. Replacing a server key requires updating clients.</p>}
    {supported === true && <div><button className={button} disabled={disabled || busy} onClick={() => void generate()}>
      {busy ? "Generating…" : "Generate key pair"}
    </button></div>}
    {supported === null && <p className="text-xs text-(--text-muted)">Checking browser key-generation support…</p>}
    {supported === false && <p className="text-xs text-(--text-muted)">Key generation unavailable: this browser or connection does not support WebCrypto X25519. Generate keys with WireGuard and enter the private key here.</p>}
    {error && <p role="alert" className="text-sm text-red-400">{error}</p>}
  </section>;
}
