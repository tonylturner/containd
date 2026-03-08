// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/tonylturner/containd/pkg/dp/anomaly"
)

func showAnomalies(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var anomalies []anomaly.Anomaly
		if err := api.getJSON(ctx, "/api/v1/anomalies", &anomalies); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		if len(anomalies) == 0 {
			fmt.Fprintln(out, "No anomalies detected.")
			return nil
		}
		t := newTable("TIME", "TYPE", "PROTOCOL", "SEVERITY", "SRC", "DST", "MESSAGE")
		for _, a := range anomalies {
			t.addRow(
				fmtTime(a.Timestamp),
				a.Type,
				a.Protocol,
				a.Severity,
				truncate(a.SourceIP, 18),
				truncate(a.DestIP, 18),
				truncate(a.Message, 60),
			)
		}
		t.render(out)
		return nil
	}
}
