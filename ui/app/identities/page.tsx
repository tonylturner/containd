"use client";

import { upsertRow } from "../../lib/config-editor";

import type { ConfigFields } from "../../lib/use-config-editor";

import { useConfigForm } from "../../lib/use-config-form";
import { ConfigEditNotice, useConfigEditor } from "../../lib/use-config-editor";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";

import { Card } from "../../components/Card";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import { EmptyState } from "../../components/EmptyState";
import { Shell } from "../../components/Shell";
import { Pagination, SearchBar, SortableHeader } from "../../components/TableControls";
import { useToast } from "../../components/ToastProvider";
import { useTableControls } from "../../hooks/useTableControls";
import { api, isAdmin, type FirewallRule, type IdentityBinding } from "../../lib/api";
import { useConfigRefresh } from "../../lib/use-config-refresh";
import {
  MAX_BINDING_IDENTITIES,
  isIP,
  parseIdentityLabels,
} from "../../lib/validate";

const MAX_BINDINGS = 4096;

/** Checks an address and its labels as the server does, before staging. */
function bindingError(ip: string, labels: string): { error: string } | { binding: IdentityBinding } {
  const address = ip.trim();
  if (!isIP(address)) return { error: `"${address}" is not an IPv4 or IPv6 address.` };
  const parsed = parseIdentityLabels(labels);
  if (!parsed.ok) return { error: parsed.error };
  if (parsed.labels.length === 0 || parsed.labels.length > MAX_BINDING_IDENTITIES) {
    return { error: `An address needs 1 to ${MAX_BINDING_IDENTITIES} identities.` };
  }
  return { binding: { ip: address, identities: parsed.labels } };
}

/** Labels that rules use but no address carries: those rules match nothing. */
function unboundRuleLabels(rules: FirewallRule[], bindings: IdentityBinding[]): string[] {
  const bound = new Set(bindings.flatMap((b) => b.identities));
  const used = new Set(rules.flatMap((r) => r.identities ?? []));
  return [...used].filter((l) => !bound.has(l)).sort();
}

export default function IdentitiesPage() {
  const toast = useToast();
  const confirm = useConfirm();
  const canEdit = isAdmin();
  const rowsDraft = useConfigEditor<IdentityBinding[]>([]);
  const { cfg: bindings, adoptConfig: adoptRows } = rowsDraft;
  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const form = useConfigForm({ ip: "", labels: "" });
  const { refreshForm } = form;
  const [ip, setIp] = form.field("ip");
  const [labels, setLabels] = form.field("labels");
  const [saving, setSaving] = useState(false);

  const refresh = useCallback(async ({ keepEdits = true }: { keepEdits?: boolean } = {}) => {
    const [res, ruleList] = await Promise.all([api.listIdentityBindings(), api.listFirewallRules()]);
    setRules(ruleList ?? []);
    if (!res.ok) {
      setLoadError(res.error);
      return;
    }
    setLoadError(null);
    adoptRows(res.data, keepEdits);
    refreshForm(res.data, keepEdits);
  }, [refreshForm, adoptRows]);

  useConfigRefresh(refresh);
  useEffect(() => {
    refresh();
  }, [refresh]);

  async function stage(binding: IdentityBinding): Promise<boolean> {
    setError(null);
    const submitted = rowsDraft.editor;
    const res = await api.setIdentityBinding(binding);
    if (!res.ok) {
      setError(res.error);
      return false;
    }
    rowsDraft.acceptRow(submitted, (rows) => upsertRow(rows, res.data, (row) => row.ip), `${JSON.stringify(binding.ip)}.`);
    toast(res.warning ? `Binding staged — commit to apply. Warning: ${res.warning}` : "Binding staged — commit to apply.", "success");
    await refresh();
    return true;
  }

  async function onCreate() {
    const checked = bindingError(ip, labels);
    if ("error" in checked) {
      setError(checked.error);
      return;
    }
    setSaving(true);
    const submitted = form.editor;
    const ok = await stage(checked.binding);
    setSaving(false);
    if (ok) form.acceptFields(submitted, ["ip", "labels"]);
  }

  function onDelete(address: string) {
    confirm.open({
      title: "Remove binding",
      message: `Remove the identities of ${address}? After commit, rules naming them stop matching its connections, including established ones that only such a rule allowed.`,
      confirmLabel: "Remove",
      variant: "danger",
      onConfirm: async () => {
        setError(null);
        const res = await api.deleteIdentityBinding(address);
        if (!res.ok) {
          setError(res.error);
          return;
        }
        rowsDraft.acceptCollection((rows) => rows.filter((row) => row.ip !== address), [`${JSON.stringify(address)}.`]);
        toast("Binding removal staged — commit to apply.", "success");
        refresh();
      },
    });
  }

  const rows = useMemo(() => bindings.map((b) => ({ ...b, labels: b.identities.join(", ") })), [bindings]);
  const table = useTableControls(rows, { defaultSort: "ip", searchKeys: ["ip", "labels"] });
  const unbound = useMemo(() => unboundRuleLabels(rules, bindings), [rules, bindings]);
  const replacing = bindings.some((b) => b.ip === ip.trim());

  return (
    <Shell
      title="Identity Bindings"
      actions={
        <button onClick={() => refresh({ keepEdits: false })} className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui">
          Refresh
        </button>
      }
    >
      <ConfigEditNotice superseded={form.editor.superseded || rowsDraft.editor.superseded} />
      {!canEdit && (
        <div className="mb-4 rounded-xs border bg-(--surface) px-4 py-3 text-sm text-(--text)">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      <p className="mb-4 text-xs text-(--text-muted)">
        Bindings tag source addresses with identity labels. A firewall rule with identities matches only
        connections opened by an address bound to one of its labels; an unbound opener matches no identity
        rule. Bindings are staged in the candidate like rules: commit to apply. See{" "}
        <Link href="/firewall/" className="text-(--amber) hover:text-(--amber)">Firewall Rules</Link>.
      </p>
      {loadError && (
        <div role="alert" aria-label="Identity bindings error" className="mb-4 rounded-xs border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          Identity bindings unavailable: {loadError}
        </div>
      )}
      {unbound.length > 0 && (
        <div role="status" aria-label="Unbound rule identities" className="mb-4 rounded-xs border border-amber/30 bg-amber/10 px-4 py-3 text-xs text-amber">
          Rules use identities no address carries, so they match nothing: <span className="font-mono">{unbound.join(", ")}</span>
        </div>
      )}

      {canEdit && (
        <Card padding="lg">
          <h2 className="text-sm font-semibold text-(--text)">Bind an address</h2>
          <div className="mt-3 grid gap-3 md:grid-cols-4">
            <input aria-label="Address" value={ip} onChange={(e) => setIp(e.target.value)} placeholder="address (e.g. 10.0.0.5)" className="input-industrial" />
            <input aria-label="Identities" value={labels} onChange={(e) => setLabels(e.target.value)} placeholder="identities (comma-separated)" className="input-industrial md:col-span-2" />
            <button onClick={onCreate} disabled={saving || (bindings.length >= MAX_BINDINGS && !replacing)} className="rounded-xs bg-(--amber) px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50">
              {saving ? "Staging..." : replacing ? "Replace binding" : "Bind"}
            </button>
          </div>
          <p className="mt-2 text-xs text-(--text-muted)">
            One unicast address per binding, 1 to {MAX_BINDING_IDENTITIES} labels of 1 to 64 bytes; labels match rule identities exactly and case-sensitively.
            {replacing && " This address is already bound; binding it replaces its identities."}
          </p>
          {error && <p className="mt-2 rounded-xs border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-sm text-red-400">{error}</p>}
        </Card>
      )}
      {!canEdit && error && <p className="mt-2 text-sm text-red-400">{error}</p>}

      {loadError && bindings.length === 0 ? null : bindings.length === 0 ? (
        <EmptyState className="mt-6" title="No identity bindings" description="Bind an address to identity labels to use them in firewall rules." />
      ) : (
        <>
          <div className="mt-6 flex items-center justify-between gap-3">
            <SearchBar value={table.search} onChange={table.setSearch} placeholder="Search addresses or identities..." />
            <span className="text-xs text-(--text-muted)">{bindings.length} of {MAX_BINDINGS} bindings</span>
          </div>
          <div className="mt-3 overflow-hidden rounded-xs border bg-(--surface) shadow-card">
            <table className="w-full text-sm">
              <thead className="bg-(--surface) text-left text-xs uppercase tracking-wide text-(--text)">
                <tr>
                  <SortableHeader label="Address" sortKey="ip" currentSort={table.sortKey} currentDir={table.sortDir} onSort={table.setSort} />
                  <SortableHeader label="Identities" sortKey="labels" currentSort={table.sortKey} currentDir={table.sortDir} onSort={table.setSort} />
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {table.data.length === 0 && (
                  <tr>
                    <td className="px-4 py-4 text-(--text-muted)" colSpan={3}>No bindings match your search.</td>
                  </tr>
                )}
                {table.data.map((b) => (
                  <BindingRow draft={rowsDraft} key={b.ip} binding={b} canEdit={canEdit} onStage={stage} onDelete={onDelete} onInvalid={setError} />
                ))}
              </tbody>
            </table>
            <Pagination page={table.page} totalPages={table.totalPages} totalItems={table.totalItems} onPage={table.setPage} />
          </div>
        </>
      )}
      <ConfirmDialog {...confirm.props} />
    </Shell>
  );
}

function BindingRow({
  draft,
  binding,
  canEdit,
  onStage,
  onDelete,
  onInvalid,
}: {
  draft: ConfigFields;
  binding: IdentityBinding;
  canEdit: boolean;
  onStage: (b: IdentityBinding) => Promise<boolean>;
  onDelete: (ip: string) => void;
  onInvalid: (error: string) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [labels, setLabels] = draft.field(`${JSON.stringify(binding.ip)}.labels`, binding.identities.join(", "));

  async function save() {
    const checked = bindingError(binding.ip, labels);
    if ("error" in checked) {
      onInvalid(checked.error);
      return;
    }
    if (await onStage(checked.binding)) setEditing(false);
  }

  return (
    <tr className="table-row-hover border-t transition-ui">
      <td className="px-4 py-3 font-mono text-xs text-(--text)">{binding.ip}</td>
      <td className="px-4 py-3">
        {editing ? (
          <input aria-label={`Identities of ${binding.ip}`} value={labels} onChange={(e) => setLabels(e.target.value)} className="input-industrial w-full" />
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {binding.identities.map((id) => (
              <span key={id} className="rounded-xs bg-[rgba(6,182,212,0.15)] px-2 py-0.5 font-mono text-[11px] text-(--cyan)">{id}</span>
            ))}
          </div>
        )}
      </td>
      <td className="px-4 py-3 text-right">
        {canEdit && (
          <div className="inline-flex gap-2">
            {editing ? (
              <>
                <button onClick={save} className="rounded-xs border bg-(--surface2) px-3 py-1 text-xs text-(--text) transition-ui">Save</button>
                <button onClick={() => { setLabels(binding.identities.join(", ")); setEditing(false); }} className="rounded-xs border bg-(--surface2) px-3 py-1 text-xs text-(--text) transition-ui">Cancel</button>
              </>
            ) : (
              <>
                <button onClick={() => setEditing(true)} className="rounded-xs border bg-(--surface2) px-3 py-1 text-xs text-(--text) transition-ui">Edit</button>
                <button onClick={() => onDelete(binding.ip)} className="rounded-xs px-3 py-1 text-xs text-red-400 transition-ui hover:bg-red-500/10">Delete</button>
              </>
            )}
          </div>
        )}
      </td>
    </tr>
  );
}
