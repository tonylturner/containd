"use client";

import { useState } from "react";

import { api } from "../../../../lib/api";
import { ConfirmDialog, useConfirm } from "../../../../components/ConfirmDialog";

/** Uploads custom ClamAV definitions to the engine and lists or deletes the stored ones. */
export function CustomDefinitions({ defs, defsPath, canEdit, notify, refresh }: {
  defs: string[];
  defsPath: string;
  canEdit: boolean;
  /** Reports an upload or delete outcome to the page. */
  notify: (message: string, ok: boolean) => void;
  refresh: () => void;
}) {
  const confirm = useConfirm();
  const [uploading, setUploading] = useState(false);

  async function upload(file: File) {
    setUploading(true);
    const result = await api.uploadAVDef(file);
    notify(result.ok ? `Uploaded ${file.name}` : (result.error || `Upload failed for ${file.name}`), result.ok);
    setUploading(false);
    refresh();
  }

  function deleteDefinition(name: string) {
    confirm.open({
      title: "Delete definition",
      message: `Delete ${name}?`,
      variant: "danger",
      confirmLabel: "Delete",
      onConfirm: async () => {
        const result = await api.deleteAVDef(name);
        notify(result.ok ? `Deleted ${name}` : (result.error || `Failed to delete ${name}`), result.ok);
        refresh();
      },
    });
  }

  return (
    <div className="mt-6">
      <ConfirmDialog {...confirm.props} />
      <h3 className="text-sm font-semibold text-(--text)">Custom definitions</h3>
      <p className="text-xs text-(--text-muted)">Upload .ndb/.ldb/.yara files into the custom defs path.</p>
      <div className="mt-3 flex flex-col gap-2">
        <div className="flex items-center gap-2">
          <label className="text-xs uppercase tracking-wide text-(--text-muted)">
            Upload file
            <input
              type="file"
              className="mt-1 text-sm text-(--text)"
              disabled={!canEdit || uploading}
              onChange={(e) => {
                if (e.target.files?.length) void upload(e.target.files[0]);
              }}
            />
          </label>
        </div>
        <div className="rounded-lg border bg-(--surface) p-3 text-xs text-(--text)">
          <div className="mb-2 font-semibold text-(--text)">Existing defs</div>
          {defsPath && <div className="mb-2 text-[10px] text-(--text-muted)">Path: {defsPath}</div>}
          {defs.length === 0 && <div className="text-(--text-muted)">None uploaded.</div>}
          {defs.length > 0 && (
            <ul className="space-y-1">
              {defs.map((d) => (
                <li key={d} className="flex items-center justify-between rounded-sm border bg-(--surface) px-2 py-1">
                  <span>{d}</span>
                  {canEdit && (
                    <button className="text-xs text-red-400 transition-ui hover:bg-red-500/10" onClick={() => deleteDefinition(d)}>
                      Delete
                    </button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
