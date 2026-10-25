// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package cli

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"

	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

func eventQueryPath(args []string) (string, bool, error) {
	v := url.Values{}
	for i := 0; i < len(args); i++ {
		key := strings.TrimPrefix(args[i], "--")
		if args[i] == "--query" {
			v.Set("query", "1")
			continue
		}
		switch args[i] {
		case "--id", "--limit", "--session", "--flow", "--kind", "--protocol", "--decision", "--verdict", "--since", "--cursor", "--apdu":
		default:
			return "", false, fmt.Errorf("unknown events flag %s", args[i])
		}
		i++
		if i == len(args) || strings.HasPrefix(args[i], "--") {
			return "", false, fmt.Errorf("--%s requires a value", key)
		}
		v.Set(key, args[i])
	}
	_, filtered, err := dpevents.ParseQuery(v)
	path := "/api/v1/events"
	if len(v) > 0 {
		path += "?" + v.Encode()
	}
	return path, filtered, err
}

func showEvents(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		path, filtered, err := eventQueryPath(args)
		if err != nil {
			return err
		}
		var events []dpevents.Event
		var page dpevents.Page
		if filtered {
			if err := api.getJSON(ctx, path, &page); err != nil {
				return err
			}
			events = page.Events
		} else if err := api.getJSON(ctx, path, &events); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		if page.EngineError != "" {
			fmt.Fprintf(out, "Engine evidence unavailable: %s\n", page.EngineError)
		}
		if page.HistoryTruncated {
			fmt.Fprintln(out, "Retained evidence only: history may have gaps from eviction or restart.")
		}
		if page.NextCursor != "" {
			fmt.Fprintf(out, "Next cursor: %s\n", page.NextCursor)
		}
		if len(events) == 0 {
			fmt.Fprintln(out, "No events.")
			return nil
		}
		t := newTable("ID", "TIME", "FLOW", "PROTO", "KIND", "SRC", "DST", "ATTRS")
		for _, ev := range events {
			src := fmt.Sprintf("%s:%d", ev.SrcIP, ev.SrcPort)
			dst := fmt.Sprintf("%s:%d", ev.DstIP, ev.DstPort)
			t.addRow(
				fmt.Sprintf("%d", ev.ID),
				fmtTime(ev.Timestamp),
				truncate(ev.FlowID, 12),
				ev.Proto,
				ev.Kind,
				truncate(src, 22),
				truncate(dst, 22),
				attrsSummary(ev.Attributes, 60),
			)
		}
		t.render(out)
		return nil
	}
}
