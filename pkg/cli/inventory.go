// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/inventory"
)

func showInventoryAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var assets []inventory.DiscoveredAsset
		if err := api.getJSON(ctx, "/api/v1/inventory", &assets); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		if len(assets) == 0 {
			fmt.Fprintln(out, "No discovered ICS assets.")
			return nil
		}
		t := newTable("IP", "PROTOCOL", "ROLE", "UNIT_IDS", "FUNC_CODES", "STATION_ADDRS", "FIRST_SEEN", "LAST_SEEN", "PKTS", "PEERS")
		for _, a := range assets {
			t.addRow(
				a.IP,
				a.Protocol,
				firstNonEmpty(a.Role, "—"),
				fmtUint8Slice(a.UnitIDs),
				fmtUint8Slice(a.FunctionCodes),
				fmtUint16Slice(a.StationAddresses),
				fmtTime(a.FirstSeen),
				fmtTime(a.LastSeen),
				fmt.Sprintf("%d", a.PacketCount),
				truncate(strings.Join(a.Peers, ","), 40),
			)
		}
		t.render(out)
		return nil
	}
}

func fmtUint8Slice(s []uint8) string {
	if len(s) == 0 {
		return "—"
	}
	parts := make([]string, len(s))
	for i, v := range s {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, ",")
}

func fmtUint16Slice(s []uint16) string {
	if len(s) == 0 {
		return "—"
	}
	parts := make([]string, len(s))
	for i, v := range s {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, ",")
}
