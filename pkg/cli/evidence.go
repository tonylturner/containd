// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/tonylturner/containd/pkg/common/evidence"
)

// showEvidenceStatus is reached through show audit --status without adding a
// second command registry entry.
func showEvidenceStatus(api *API) Command {
	return func(ctx context.Context, out io.Writer, _ []string) error {
		status := evidence.Status{Audit: evidence.AuditStatus{State: evidence.StateUnknown}}
		if err := api.getJSON(ctx, "/api/v1/evidence/status", &status); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		fmt.Fprintf(out, "Audit persistence: %s\nFailed writes since process start: %d\n", status.Audit.State, status.Audit.Failures)
		fmt.Fprintln(out, "Operations continue when audit writes fail; missing records are not restored by recovery.")
		if status.Audit.LastFailureAt != nil {
			fmt.Fprintf(out, "Last failure: %s\n", fmtTime(*status.Audit.LastFailureAt))
		}
		if status.Audit.LastSuccessAt != nil {
			fmt.Fprintf(out, "Last success: %s\n", fmtTime(*status.Audit.LastSuccessAt))
		}
		if status.Audit.LastError != "" {
			fmt.Fprintf(out, "Last error: %s\n", status.Audit.LastError)
		}
		if len(status.Forwarding) == 0 {
			fmt.Fprintln(out, "No forwarding streams reported.")
			return nil
		}
		t := newTable("DESTINATION", "SOURCE", "STATE", "SENT THROUGH", "BACKLOG", "LOST", "ERROR")
		for _, row := range status.Forwarding {
			t.addRow(row.Destination, string(row.Source), string(row.State), row.SentThrough,
				fmt.Sprint(row.Backlog), fmt.Sprint(row.Lost), row.LastError)
		}
		t.render(out)
		return nil
	}
}

func writeSyslogEventStatus(out io.Writer, value any) {
	streams, ok := value.([]any)
	if !ok {
		fmt.Fprintln(out, "  telemetry: progress unknown")
		return
	}
	fmt.Fprintln(out, "  telemetry: best effort with retries; new destinations start at tail (no backfill)")
	fmt.Fprintln(out, "  sent is local transport acceptance; continuity gaps mean additional loss is unknown")
	for _, raw := range streams {
		row, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		fmt.Fprintf(out, "    %s source=%s\n", fmtAny(row["destination"]), fmtAny(row["source"]))
		for _, key := range []string{"backlog", "sent", "failed", "lost", "continuity_unknown", "epoch", "offset", "last_success", "last_error"} {
			fmt.Fprintf(out, "      %s: %s\n", key, firstNonEmpty(fmtAny(row[key]), "—"))
		}
	}
}
