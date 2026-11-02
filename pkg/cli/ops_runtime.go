// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

func opsConfirmed(api *API, name, path string) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 1 || args[0] != "CONFIRM" {
			return fmt.Errorf("usage: %s CONFIRM (immediate)", name)
		}
		// No body: PCAP start must use committed settings, not an empty override.
		return opsImmediate(ctx, api, out, http.MethodPost, path, nil)
	}
}

func opsRetryProtection(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 3 || args[0] == "" || args[1] == "" || args[2] != "CONFIRM" {
			return fmt.Errorf("usage: retry protection <boot-id> <apply-id> CONFIRM (immediate; inspect show protection first)")
		}
		return opsImmediate(ctx, api, out, http.MethodPost, "/api/v1/dataplane/protection/retry", map[string]string{"bootId": args[0], "applyId": args[1]})
	}
}

func opsRevokeConnection(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		const usage = "usage: revoke connection <connection|client-service> <duration-seconds> <tcp|udp|icmp|icmpv6> <src> <dst> <sport> <dport> CONFIRM (ICMP: <id> <type> <code> instead of ports; immediate)"
		if len(args) < 8 || args[len(args)-1] != "CONFIRM" {
			return fmt.Errorf("%s", usage)
		}
		if args[0] != "connection" && args[0] != "client-service" {
			return fmt.Errorf("%s", usage)
		}
		duration, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("invalid duration: %w", err)
		}
		payload := map[string]any{"scope": args[0], "durationSecs": duration, "proto": args[2], "src": args[3], "dst": args[4]}
		var keys []string
		switch args[2] {
		case "tcp", "udp":
			keys = []string{"sport", "dport"}
		case "icmp", "icmpv6":
			keys = []string{"icmpId", "icmpType", "icmpCode"}
		default:
			return fmt.Errorf("%s", usage)
		}
		if len(args) != 6+len(keys) {
			return fmt.Errorf("%s", usage)
		}
		for i, key := range keys {
			value, err := strconv.Atoi(args[5+i])
			if err != nil {
				return fmt.Errorf("invalid %s: %w", key, err)
			}
			payload[key] = value
		}
		return opsImmediate(ctx, api, out, http.MethodPost, "/api/v1/conntrack/kill", payload)
	}
}
