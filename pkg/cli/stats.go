// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"context"
	"fmt"
	"io"
	"strconv"

	"github.com/tonylturner/containd/pkg/dp/stats"
)

func showStatsProtocols(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var result []stats.ProtoStats
		if err := api.getJSON(ctx, "/api/v1/stats/protocols", &result); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		if len(result) == 0 {
			fmt.Fprintln(out, "No protocol statistics.")
			return nil
		}
		t := newTable("PROTOCOL", "PACKETS", "BYTES", "EVENTS", "READS", "WRITES", "ALERTS", "LAST_SEEN")
		for _, ps := range result {
			t.addRow(
				ps.Protocol,
				fmt.Sprintf("%d", ps.PacketCount),
				fmt.Sprintf("%d", ps.ByteCount),
				fmt.Sprintf("%d", ps.EventCount),
				fmt.Sprintf("%d", ps.ReadCount),
				fmt.Sprintf("%d", ps.WriteCount),
				fmt.Sprintf("%d", ps.AlertCount),
				fmtTime(ps.LastSeen),
			)
		}
		t.render(out)
		return nil
	}
}

func showStatsTopTalkers(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		n := 10
		if len(args) > 0 {
			if v, err := strconv.Atoi(args[0]); err == nil && v > 0 {
				n = v
			}
		}
		path := fmt.Sprintf("/api/v1/stats/top-talkers?n=%d", n)
		var result []stats.FlowStats
		if err := api.getJSON(ctx, path, &result); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		if len(result) == 0 {
			fmt.Fprintln(out, "No flow statistics.")
			return nil
		}
		t := newTable("SRC_IP", "DST_IP", "PROTOCOL", "PACKETS", "BYTES")
		for _, fs := range result {
			t.addRow(
				fs.SrcIP,
				fs.DstIP,
				fs.Protocol,
				fmt.Sprintf("%d", fs.Packets),
				fmt.Sprintf("%d", fs.Bytes),
			)
		}
		t.render(out)
		return nil
	}
}
