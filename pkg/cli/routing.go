// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func showRoutingAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 0 {
			return fmt.Errorf("usage: show routing")
		}
		var routing config.RoutingConfig
		if err := api.getJSON(ctx, "/api/v1/routing", &routing); err != nil {
			return err
		}

		if out == nil {
			return nil
		}

		rt := newTable("DST", "GATEWAY", "IFACE", "TABLE", "METRIC")
		for _, r := range routing.Routes {
			rt.addRow(
				r.Dst,
				emptyDash(r.Gateway),
				emptyDash(r.Iface),
				intOrDash(r.Table),
				intOrDash(r.Metric),
			)
		}
		if len(routing.Routes) == 0 {
			rt.addRow("—", "—", "—", "—", "—")
		}

		rules := newTable("PRIORITY", "SRC", "DST", "TABLE")
		for _, r := range routing.Rules {
			prio := "auto"
			if r.Priority != 0 {
				prio = fmt.Sprintf("%d", r.Priority)
			}
			rules.addRow(
				prio,
				emptyDash(r.Src),
				emptyDash(r.Dst),
				fmt.Sprintf("%d", r.Table),
			)
		}
		if len(routing.Rules) == 0 {
			rules.addRow("—", "—", "—", "—")
		}

		fmt.Fprintln(out, "Static routes:")
		rt.render(out)
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Policy rules (ip rules):")
		rules.render(out)
		return nil
	}
}

func routingReconcileAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 1 || strings.TrimSpace(args[0]) != "REPLACE" {
			return fmt.Errorf("usage: diag routing reconcile REPLACE")
		}
		return api.postJSON(ctx, "/api/v1/routing/reconcile", map[string]string{"confirm": "REPLACE"}, out)
	}
}

func emptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return strings.TrimSpace(s)
}

func intOrDash(v int) string {
	if v == 0 {
		return "0"
	}
	if v < 0 {
		return "—"
	}
	return fmt.Sprintf("%d", v)
}
