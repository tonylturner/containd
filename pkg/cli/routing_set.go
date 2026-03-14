// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func setRouteAddAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if api == nil {
			return fmt.Errorf("api unavailable")
		}
		rt, err := parseRouteAddArgs(args)
		if err != nil {
			return err
		}
		if err := addRouteConfig(ctx, api, rt); err != nil {
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
		match, filters, err := parseRouteDeleteArgs(args)
		if err != nil {
			return err
		}
		if err := deleteMatchingRoutes(ctx, api, match, filters); err != nil {
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
		rule, err := parseIPRuleAddArgs(args)
		if err != nil {
			return err
		}
		if err := addIPRuleConfig(ctx, api, rule); err != nil {
			return err
		}
		if out != nil {
			_ = showRoutingAPI(api)(ctx, out, nil)
		}
		return nil
	}
}

func parseRouteAddArgs(args []string) (config.StaticRoute, error) {
	if len(args) < 1 {
		return config.StaticRoute{}, fmt.Errorf("usage: set route add <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]")
	}
	dst := strings.TrimSpace(args[0])
	if dst == "" {
		return config.StaticRoute{}, fmt.Errorf("dst is required")
	}
	rt := config.StaticRoute{Dst: dst}
	for i := 1; i < len(args); i++ {
		switch strings.ToLower(strings.TrimSpace(args[i])) {
		case "via", "gw", "gateway":
			value, next, err := routingOptionValue("set route add <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]", args, i)
			if err != nil {
				return config.StaticRoute{}, err
			}
			rt.Gateway = value
			i = next
		case "dev", "iface":
			value, next, err := routingOptionValue("set route add <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]", args, i)
			if err != nil {
				return config.StaticRoute{}, err
			}
			rt.Iface = value
			i = next
		case "table":
			n, next, err := routingIntOption("set route add <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]", args, i, 0, 252, "table")
			if err != nil {
				return config.StaticRoute{}, err
			}
			rt.Table = n
			i = next
		case "metric":
			n, next, err := routingIntOption("set route add <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]", args, i, 0, 1000000, "metric")
			if err != nil {
				return config.StaticRoute{}, err
			}
			rt.Metric = n
			i = next
		default:
			return config.StaticRoute{}, fmt.Errorf("unexpected token %q (usage: set route add <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>])", args[i])
		}
	}
	return rt, nil
}

func addRouteConfig(ctx context.Context, api *API, rt config.StaticRoute) error {
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
	return api.postJSON(ctx, "/api/v1/routing", routing, nil)
}

func parseIPRuleAddArgs(args []string) (config.PolicyRule, error) {
	if len(args) < 1 {
		return config.PolicyRule{}, fmt.Errorf("usage: set ip rule add <table> [src <cidr>] [dst <cidr>] [priority <n>]")
	}
	table, err := strconv.Atoi(strings.TrimSpace(args[0]))
	if err != nil || table <= 0 || table > 252 {
		return config.PolicyRule{}, fmt.Errorf("invalid table %q", args[0])
	}
	rule := config.PolicyRule{Table: table}
	for i := 1; i < len(args); i++ {
		switch strings.ToLower(strings.TrimSpace(args[i])) {
		case "src":
			value, next, err := routingOptionValue("set ip rule add <table> [src <cidr>] [dst <cidr>] [priority <n>]", args, i)
			if err != nil {
				return config.PolicyRule{}, err
			}
			rule.Src = value
			i = next
		case "dst":
			value, next, err := routingOptionValue("set ip rule add <table> [src <cidr>] [dst <cidr>] [priority <n>]", args, i)
			if err != nil {
				return config.PolicyRule{}, err
			}
			rule.Dst = value
			i = next
		case "priority", "prio":
			n, next, err := routingIntOption("set ip rule add <table> [src <cidr>] [dst <cidr>] [priority <n>]", args, i, 0, 1000000, "priority")
			if err != nil {
				return config.PolicyRule{}, err
			}
			rule.Priority = n
			i = next
		default:
			return config.PolicyRule{}, fmt.Errorf("unexpected token %q (usage: set ip rule add <table> [src <cidr>] [dst <cidr>] [priority <n>])", args[i])
		}
	}
	return rule, nil
}

func addIPRuleConfig(ctx context.Context, api *API, rule config.PolicyRule) error {
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
	return api.postJSON(ctx, "/api/v1/routing", routing, nil)
}

func setIPRuleDelAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if api == nil {
			return fmt.Errorf("api unavailable")
		}
		table, match, filters, deleteAll, err := parseIPRuleDeleteArgs(args)
		if err != nil {
			return err
		}
		if deleteAll {
			return deleteAllIPRulesForTable(ctx, out, api, table)
		}
		if err := deleteMatchingIPRules(ctx, api, match, filters); err != nil {
			return err
		}
		if out != nil {
			_ = showRoutingAPI(api)(ctx, out, nil)
		}
		return nil
	}
}

type routeDeleteFilters struct {
	matchGateway bool
	matchIface   bool
	matchTable   bool
	matchMetric  bool
}

type ipRuleDeleteFilters struct {
	matchSrc      bool
	matchDst      bool
	matchPriority bool
}

func parseRouteDeleteArgs(args []string) (config.StaticRoute, routeDeleteFilters, error) {
	if len(args) < 1 {
		return config.StaticRoute{}, routeDeleteFilters{}, fmt.Errorf("usage: set route del <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]")
	}
	dst := strings.TrimSpace(args[0])
	if dst == "" {
		return config.StaticRoute{}, routeDeleteFilters{}, fmt.Errorf("dst is required")
	}
	match := config.StaticRoute{Dst: dst}
	filters := routeDeleteFilters{}
	for i := 1; i < len(args); i++ {
		switch strings.ToLower(strings.TrimSpace(args[i])) {
		case "via", "gw", "gateway":
			value, next, err := routingOptionValue("set route del <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]", args, i)
			if err != nil {
				return config.StaticRoute{}, routeDeleteFilters{}, err
			}
			match.Gateway = value
			filters.matchGateway = true
			i = next
		case "dev", "iface":
			value, next, err := routingOptionValue("set route del <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]", args, i)
			if err != nil {
				return config.StaticRoute{}, routeDeleteFilters{}, err
			}
			match.Iface = value
			filters.matchIface = true
			i = next
		case "table":
			n, next, err := routingIntOption("set route del <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]", args, i, 0, 252, "table")
			if err != nil {
				return config.StaticRoute{}, routeDeleteFilters{}, err
			}
			match.Table = n
			filters.matchTable = true
			i = next
		case "metric":
			n, next, err := routingIntOption("set route del <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>]", args, i, 0, 1000000, "metric")
			if err != nil {
				return config.StaticRoute{}, routeDeleteFilters{}, err
			}
			match.Metric = n
			filters.matchMetric = true
			i = next
		default:
			return config.StaticRoute{}, routeDeleteFilters{}, fmt.Errorf("unexpected token %q (usage: set route del <dst|default> [via <gw>] [dev <iface>] [table <n>] [metric <n>])", args[i])
		}
	}
	return match, filters, nil
}

func deleteMatchingRoutes(ctx context.Context, api *API, match config.StaticRoute, filters routeDeleteFilters) error {
	var routing config.RoutingConfig
	if err := api.getJSON(ctx, "/api/v1/routing", &routing); err != nil {
		return err
	}
	matches := 0
	filtered := make([]config.StaticRoute, 0, len(routing.Routes))
	for _, r := range routing.Routes {
		if !routeMatches(r, match, filters.matchGateway, filters.matchIface, filters.matchTable, filters.matchMetric) {
			filtered = append(filtered, r)
			continue
		}
		matches++
	}
	if matches == 0 {
		return fmt.Errorf("no matching route found")
	}
	if matches > 1 && !(filters.matchGateway || filters.matchIface || filters.matchTable || filters.matchMetric) {
		return fmt.Errorf("multiple routes match; specify via/dev/table/metric to disambiguate")
	}
	routing.Routes = filtered
	return api.postJSON(ctx, "/api/v1/routing", routing, nil)
}

func parseIPRuleDeleteArgs(args []string) (int, config.PolicyRule, ipRuleDeleteFilters, bool, error) {
	if len(args) < 1 {
		return 0, config.PolicyRule{}, ipRuleDeleteFilters{}, false, fmt.Errorf("usage: set ip rule del <table> [src <cidr>] [dst <cidr>] [priority <n>] | set ip rule del <table> all")
	}
	table, err := strconv.Atoi(strings.TrimSpace(args[0]))
	if err != nil || table <= 0 || table > 252 {
		return 0, config.PolicyRule{}, ipRuleDeleteFilters{}, false, fmt.Errorf("invalid table %q", args[0])
	}
	if len(args) == 2 && strings.EqualFold(strings.TrimSpace(args[1]), "all") {
		return table, config.PolicyRule{}, ipRuleDeleteFilters{}, true, nil
	}
	match := config.PolicyRule{Table: table}
	filters := ipRuleDeleteFilters{}
	for i := 1; i < len(args); i++ {
		switch strings.ToLower(strings.TrimSpace(args[i])) {
		case "src":
			value, next, err := routingOptionValue("set ip rule del <table> [src <cidr>] [dst <cidr>] [priority <n>] | set ip rule del <table> all", args, i)
			if err != nil {
				return 0, config.PolicyRule{}, ipRuleDeleteFilters{}, false, err
			}
			match.Src = value
			filters.matchSrc = true
			i = next
		case "dst":
			value, next, err := routingOptionValue("set ip rule del <table> [src <cidr>] [dst <cidr>] [priority <n>] | set ip rule del <table> all", args, i)
			if err != nil {
				return 0, config.PolicyRule{}, ipRuleDeleteFilters{}, false, err
			}
			match.Dst = value
			filters.matchDst = true
			i = next
		case "priority", "prio":
			n, next, err := routingIntOption("set ip rule del <table> [src <cidr>] [dst <cidr>] [priority <n>] | set ip rule del <table> all", args, i, 0, 1000000, "priority")
			if err != nil {
				return 0, config.PolicyRule{}, ipRuleDeleteFilters{}, false, err
			}
			match.Priority = n
			filters.matchPriority = true
			i = next
		default:
			return 0, config.PolicyRule{}, ipRuleDeleteFilters{}, false, fmt.Errorf("unexpected token %q (usage: set ip rule del <table> [src <cidr>] [dst <cidr>] [priority <n>] | set ip rule del <table> all)", args[i])
		}
	}
	return table, match, filters, false, nil
}

func deleteMatchingIPRules(ctx context.Context, api *API, match config.PolicyRule, filters ipRuleDeleteFilters) error {
	var routing config.RoutingConfig
	if err := api.getJSON(ctx, "/api/v1/routing", &routing); err != nil {
		return err
	}
	matches := 0
	filtered := make([]config.PolicyRule, 0, len(routing.Rules))
	for _, r := range routing.Rules {
		if !ipRuleMatches(r, match, filters.matchSrc, filters.matchDst, filters.matchPriority) {
			filtered = append(filtered, r)
			continue
		}
		matches++
	}
	if matches == 0 {
		return fmt.Errorf("no matching rule found")
	}
	if matches > 1 && !(filters.matchSrc || filters.matchDst || filters.matchPriority) {
		return fmt.Errorf("multiple rules match; specify src/dst/priority or use 'all'")
	}
	routing.Rules = filtered
	return api.postJSON(ctx, "/api/v1/routing", routing, nil)
}

func routingOptionValue(usage string, args []string, i int) (string, int, error) {
	i++
	if i >= len(args) {
		return "", i, fmt.Errorf("usage: %s", usage)
	}
	return strings.TrimSpace(args[i]), i, nil
}

func routingIntOption(usage string, args []string, i int, min int, max int, label string) (int, int, error) {
	value, next, err := routingOptionValue(usage, args, i)
	if err != nil {
		return 0, next, err
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < min || n > max {
		return 0, next, fmt.Errorf("invalid %s %q", label, value)
	}
	return n, next, nil
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
