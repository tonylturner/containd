// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
)

func analyzePcapAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: analyze pcap <filename>")
		}
		filename := args[0]

		f, err := os.Open(filename)
		if err != nil {
			return fmt.Errorf("open %s: %w", filename, err)
		}
		defer f.Close()

		// Use the management API to relay to the engine's analyze endpoint.
		if api.Client == nil {
			api.Client = defaultHTTPClient
		}

		// Build a multipart upload to /api/v1/pcap/analyze.
		type analysisResult struct {
			PacketCount int              `json:"packetCount"`
			ByteCount   int              `json:"byteCount"`
			Duration    float64          `json:"duration"` // nanoseconds
			Protocols   map[string]int   `json:"protocols"`
			Flows       []struct {
				Key      string `json:"key"`
				Protocol string `json:"protocol"`
				Packets  int    `json:"packets"`
				Bytes    int    `json:"bytes"`
				Events   int    `json:"events"`
			} `json:"flows"`
			Events []struct {
				Proto      string         `json:"Proto"`
				Kind       string         `json:"Kind"`
				FlowID     string         `json:"FlowID"`
				Attributes map[string]any `json:"Attributes"`
			} `json:"events"`
		}

		var result analysisResult
		if err := api.postMultipartFile(ctx, "/api/v1/pcap/analyze", filename, f, &result); err != nil {
			return err
		}

		if out == nil {
			return nil
		}

		// Summary.
		fmt.Fprintf(out, "Packets:   %d\n", result.PacketCount)
		fmt.Fprintf(out, "Bytes:     %d\n", result.ByteCount)
		fmt.Fprintf(out, "Flows:     %d\n", len(result.Flows))

		// Protocol breakdown.
		if len(result.Protocols) > 0 {
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Protocol Breakdown:")
			protos := make([]string, 0, len(result.Protocols))
			for k := range result.Protocols {
				protos = append(protos, k)
			}
			sort.Strings(protos)
			t := newTable("PROTOCOL", "EVENTS")
			for _, p := range protos {
				t.addRow(p, fmt.Sprintf("%d", result.Protocols[p]))
			}
			t.render(out)
		}

		// Top events (up to 20).
		if len(result.Events) > 0 {
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Events:")
			t := newTable("PROTO", "KIND", "FLOW", "ATTRS")
			limit := len(result.Events)
			if limit > 20 {
				limit = 20
			}
			for _, ev := range result.Events[:limit] {
				t.addRow(ev.Proto, ev.Kind, truncate(ev.FlowID, 12), attrsSummary(ev.Attributes, 60))
			}
			t.render(out)
			if len(result.Events) > 20 {
				fmt.Fprintf(out, "... and %d more events\n", len(result.Events)-20)
			}
		}

		return nil
	}
}
