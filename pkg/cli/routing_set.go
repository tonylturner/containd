package cli

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/containd/containd/pkg/cp/config"
)

func setRouteAddAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if api == nil {
			return fmt.Errorf("api unavailable")
		}
		if len(args) < 1 {
			return fmt.Errorf("usage: set route add <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]")
		}
		dst := strings.TrimSpace(args[0])
		if dst == "" {
			return fmt.Errorf("dst is required")
		}
		rt := config.StaticRoute{Dst: dst}

		for i := 1; i < len(args); i++ {
			switch strings.ToLower(strings.TrimSpace(args[i])) {
			case "via", "gw", "gateway":
				i++
				if i >= len(args) {
					return fmt.Errorf("usage: set route add <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]")
				}
				rt.Gateway = strings.TrimSpace(args[i])
			case "dev", "iface":
				i++
				if i >= len(args) {
					return fmt.Errorf("usage: set route add <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]")
				}
				rt.Iface = strings.TrimSpace(args[i])
			case "table":
				i++
				if i >= len(args) {
					return fmt.Errorf("usage: set route add <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]")
				}
				n, err := strconv.Atoi(strings.TrimSpace(args[i]))
				if err != nil || n < 0 || n > 252 {
					return fmt.Errorf("invalid table %q", args[i])
				}
				rt.Table = n
			case "metric":
				i++
				if i >= len(args) {
					return fmt.Errorf("usage: set route add <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]")
				}
				n, err := strconv.Atoi(strings.TrimSpace(args[i]))
				if err != nil || n < 0 || n > 1000000 {
					return fmt.Errorf("invalid metric %q", args[i])
				}
				rt.Metric = n
			default:
				return fmt.Errorf("unexpected token %q (usage: set route add <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>])", args[i])
			}
		}

		var routing config.RoutingConfig
		if err := api.getJSON(ctx, "/api/v1/routing", &routing); err != nil {
			return err
		}
		for _, existing := range routing.Routes {
			if routesEqual(existing, rt) {
				return fmt.Errorf("route already exists")
			}
		}
		routing.Routes = append(routing.Routes, rt)
		if err := api.postJSON(ctx, "/api/v1/routing", routing, nil); err != nil {
			return err
		}
		if out != nil {
			_ = showRoutingAPI(api)(ctx, out, nil)
		}
		return nil
	}
}

func setRouteDelAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if api == nil {
			return fmt.Errorf("api unavailable")
		}
		if len(args) < 1 {
			return fmt.Errorf("usage: set route del <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]")
		}
		dst := strings.TrimSpace(args[0])
		if dst == "" {
			return fmt.Errorf("dst is required")
		}
		match := config.StaticRoute{Dst: dst}
		matchGateway := false
		matchIface := false
		matchTable := false
		matchMetric := false

		for i := 1; i < len(args); i++ {
			switch strings.ToLower(strings.TrimSpace(args[i])) {
			case "via", "gw", "gateway":
				i++
				if i >= len(args) {
					return fmt.Errorf("usage: set route del <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]")
				}
				match.Gateway = strings.TrimSpace(args[i])
				matchGateway = true
			case "dev", "iface":
				i++
				if i >= len(args) {
					return fmt.Errorf("usage: set route del <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]")
				}
				match.Iface = strings.TrimSpace(args[i])
				matchIface = true
			case "table":
				i++
				if i >= len(args) {
					return fmt.Errorf("usage: set route del <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]")
				}
				n, err := strconv.Atoi(strings.TrimSpace(args[i]))
				if err != nil || n < 0 || n > 252 {
					return fmt.Errorf("invalid table %q", args[i])
				}
				match.Table = n
				matchTable = true
			case "metric":
				i++
				if i >= len(args) {
					return fmt.Errorf("usage: set route del <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]")
				}
				n, err := strconv.Atoi(strings.TrimSpace(args[i]))
				if err != nil || n < 0 || n > 1000000 {
					return fmt.Errorf("invalid metric %q", args[i])
				}
				match.Metric = n
				matchMetric = true
			default:
				return fmt.Errorf("unexpected token %q (usage: set route del <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>])", args[i])
			}
		}

		var routing config.RoutingConfig
		if err := api.getJSON(ctx, "/api/v1/routing", &routing); err != nil {
			return err
		}

		matches := 0
		filtered := make([]config.StaticRoute, 0, len(routing.Routes))
		for _, r := range routing.Routes {
			if !routeMatches(r, match, matchGateway, matchIface, matchTable, matchMetric) {
				filtered = append(filtered, r)
				continue
			}
			matches++
		}
		if matches == 0 {
			return fmt.Errorf("no matching route found")
		}
		if matches > 1 && !(matchGateway || matchIface || matchTable || matchMetric) {
			return fmt.Errorf("multiple routes match; specify via/dev/table/metric to disambiguate")
		}

		routing.Routes = filtered
		if err := api.postJSON(ctx, "/api/v1/routing", routing, nil); err != nil {
			return err
		}
		if out != nil {
			_ = showRoutingAPI(api)(ctx, out, nil)
		}
		return nil
	}
}

func setIPRuleAddAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if api == nil {
			return fmt.Errorf("api unavailable")
		}
		if len(args) < 1 {
			return fmt.Errorf("usage: set ip rule add <table> [src <cidr>] [dst <cidr>] [priority <n>]")
		}
		table, err := strconv.Atoi(strings.TrimSpace(args[0]))
		if err != nil || table <= 0 || table > 252 {
			return fmt.Errorf("invalid table %q", args[0])
		}
		rule := config.PolicyRule{Table: table}
		for i := 1; i < len(args); i++ {
			switch strings.ToLower(strings.TrimSpace(args[i])) {
			case "src":
				i++
				if i >= len(args) {
					return fmt.Errorf("usage: set ip rule add <table> [src <cidr>] [dst <cidr>] [priority <n>]")
				}
				rule.Src = strings.TrimSpace(args[i])
			case "dst":
				i++
				if i >= len(args) {
					return fmt.Errorf("usage: set ip rule add <table> [src <cidr>] [dst <cidr>] [priority <n>]")
				}
				rule.Dst = strings.TrimSpace(args[i])
			case "priority", "prio":
				i++
				if i >= len(args) {
					return fmt.Errorf("usage: set ip rule add <table> [src <cidr>] [dst <cidr>] [priority <n>]")
				}
				n, err := strconv.Atoi(strings.TrimSpace(args[i]))
				if err != nil || n < 0 || n > 1000000 {
					return fmt.Errorf("invalid priority %q", args[i])
				}
				rule.Priority = n
			default:
				return fmt.Errorf("unexpected token %q (usage: set ip rule add <table> [src <cidr>] [dst <cidr>] [priority <n>])", args[i])
			}
		}

		var routing config.RoutingConfig
		if err := api.getJSON(ctx, "/api/v1/routing", &routing); err != nil {
			return err
		}
		for _, existing := range routing.Rules {
			if rulesEqual(existing, rule) {
				return fmt.Errorf("rule already exists")
			}
		}
		routing.Rules = append(routing.Rules, rule)
		if err := api.postJSON(ctx, "/api/v1/routing", routing, nil); err != nil {
			return err
		}
		if out != nil {
			_ = showRoutingAPI(api)(ctx, out, nil)
		}
		return nil
	}
}

func setIPRuleDelAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if api == nil {
			return fmt.Errorf("api unavailable")
		}
		if len(args) < 1 {
			return fmt.Errorf("usage: set ip rule del <table> [src <cidr>] [dst <cidr>] [priority <n>] | set ip rule del <table> all")
		}
		table, err := strconv.Atoi(strings.TrimSpace(args[0]))
		if err != nil || table <= 0 || table > 252 {
			return fmt.Errorf("invalid table %q", args[0])
		}
		if len(args) == 2 && strings.EqualFold(strings.TrimSpace(args[1]), "all") {
			return deleteAllIPRulesForTable(ctx, out, api, table)
		}
		match := config.PolicyRule{Table: table}
		matchSrc := false
		matchDst := false
		matchPriority := false
		for i := 1; i < len(args); i++ {
			switch strings.ToLower(strings.TrimSpace(args[i])) {
			case "src":
				i++
				if i >= len(args) {
					return fmt.Errorf("usage: set ip rule del <table> [src <cidr>] [dst <cidr>] [priority <n>] | set ip rule del <table> all")
				}
				match.Src = strings.TrimSpace(args[i])
				matchSrc = true
			case "dst":
				i++
				if i >= len(args) {
					return fmt.Errorf("usage: set ip rule del <table> [src <cidr>] [dst <cidr>] [priority <n>] | set ip rule del <table> all")
				}
				match.Dst = strings.TrimSpace(args[i])
				matchDst = true
			case "priority", "prio":
				i++
				if i >= len(args) {
					return fmt.Errorf("usage: set ip rule del <table> [src <cidr>] [dst <cidr>] [priority <n>] | set ip rule del <table> all")
				}
				n, err := strconv.Atoi(strings.TrimSpace(args[i]))
				if err != nil || n < 0 || n > 1000000 {
					return fmt.Errorf("invalid priority %q", args[i])
				}
				match.Priority = n
				matchPriority = true
			default:
				return fmt.Errorf("unexpected token %q (usage: set ip rule del <table> [src <cidr>] [dst <cidr>] [priority <n>] | set ip rule del <table> all)", args[i])
			}
		}

		var routing config.RoutingConfig
		if err := api.getJSON(ctx, "/api/v1/routing", &routing); err != nil {
			return err
		}
		matches := 0
		filtered := make([]config.PolicyRule, 0, len(routing.Rules))
		for _, r := range routing.Rules {
			if !ipRuleMatches(r, match, matchSrc, matchDst, matchPriority) {
				filtered = append(filtered, r)
				continue
			}
			matches++
		}
		if matches == 0 {
			return fmt.Errorf("no matching rule found")
		}
		if matches > 1 && !(matchSrc || matchDst || matchPriority) {
			return fmt.Errorf("multiple rules match; specify src/dst/priority or use 'all'")
		}
		routing.Rules = filtered
		if err := api.postJSON(ctx, "/api/v1/routing", routing, nil); err != nil {
			return err
		}
		if out != nil {
			_ = showRoutingAPI(api)(ctx, out, nil)
		}
		return nil
	}
}

func deleteAllIPRulesForTable(ctx context.Context, out io.Writer, api *API, table int) error {
	var routing config.RoutingConfig
	if err := api.getJSON(ctx, "/api/v1/routing", &routing); err != nil {
		return err
	}
	filtered := make([]config.PolicyRule, 0, len(routing.Rules))
	removed := 0
	for _, r := range routing.Rules {
		if r.Table == table {
			removed++
			continue
		}
		filtered = append(filtered, r)
	}
	if removed == 0 {
		return fmt.Errorf("no rules found for table %d", table)
	}
	routing.Rules = filtered
	if err := api.postJSON(ctx, "/api/v1/routing", routing, nil); err != nil {
		return err
	}
	if out != nil {
		_ = showRoutingAPI(api)(ctx, out, nil)
	}
	return nil
}

func routesEqual(a, b config.StaticRoute) bool {
	return normRouteDst(a.Dst) == normRouteDst(b.Dst) &&
		strings.TrimSpace(a.Gateway) == strings.TrimSpace(b.Gateway) &&
		strings.TrimSpace(a.Iface) == strings.TrimSpace(b.Iface) &&
		a.Table == b.Table &&
		a.Metric == b.Metric
}

func routeMatches(r, match config.StaticRoute, matchGateway, matchIface, matchTable, matchMetric bool) bool {
	if normRouteDst(r.Dst) != normRouteDst(match.Dst) {
		return false
	}
	if matchGateway && strings.TrimSpace(r.Gateway) != strings.TrimSpace(match.Gateway) {
		return false
	}
	if matchIface && strings.TrimSpace(r.Iface) != strings.TrimSpace(match.Iface) {
		return false
	}
	if matchTable && r.Table != match.Table {
		return false
	}
	if matchMetric && r.Metric != match.Metric {
		return false
	}
	return true
}

func normRouteDst(dst string) string {
	dst = strings.TrimSpace(dst)
	if strings.EqualFold(dst, "default") {
		return "default"
	}
	return dst
}

func rulesEqual(a, b config.PolicyRule) bool {
	return a.Table == b.Table &&
		a.Priority == b.Priority &&
		strings.TrimSpace(a.Src) == strings.TrimSpace(b.Src) &&
		strings.TrimSpace(a.Dst) == strings.TrimSpace(b.Dst)
}

func ipRuleMatches(r, match config.PolicyRule, matchSrc, matchDst, matchPriority bool) bool {
	if r.Table != match.Table {
		return false
	}
	if matchPriority && r.Priority != match.Priority {
		return false
	}
	if matchSrc && strings.TrimSpace(r.Src) != strings.TrimSpace(match.Src) {
		return false
	}
	if matchDst && strings.TrimSpace(r.Dst) != strings.TrimSpace(match.Dst) {
		return false
	}
	return true
}
