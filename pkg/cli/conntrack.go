// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
)

func showConntrackAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		limit := 200
		if len(args) >= 1 {
			if v, err := strconv.Atoi(strings.TrimSpace(args[0])); err == nil && v > 0 {
				limit = v
			}
		}

		var entries []conntrack.Entry
		path := "/api/v1/conntrack?limit=" + url.QueryEscape(fmt.Sprintf("%d", limit))
		if err := api.getJSON(ctx, path, &entries); err != nil {
			return err
		}

		t := newTable("PROTO", "STATE", "SRC", "SPORT", "DST", "DPORT", "MARK", "ASSURED", "TTL")
		for _, e := range entries {
			t.addRow(
				firstNonEmpty(e.Proto, "—"),
				firstNonEmpty(e.State, "—"),
				firstNonEmpty(e.Src, "—"),
				firstNonEmpty(e.Sport, "—"),
				firstNonEmpty(e.Dst, "—"),
				firstNonEmpty(e.Dport, "—"),
				firstNonEmpty(e.Mark, "—"),
				yesNoStr(e.Assured),
				func() string {
					if e.TimeoutSecs <= 0 {
						return "—"
					}
					return fmt.Sprintf("%ds", e.TimeoutSecs)
				}(),
			)
		}
		t.render(out)
		if len(entries) == 0 {
			fmt.Fprintln(out, "")
			fmt.Fprintln(out, "No conntrack entries returned (may require running inside the Linux appliance with conntrack available).")
		}
		return nil
	}
}
