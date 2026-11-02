// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"fmt"
	"io"
)

func registerAVServiceCommands(r *Registry, api *API) {
	const av = "/api/v1/services/av"
	registerServiceFields(r, api, "av", av, []serviceField{
		{"enabled", "enabled", serviceBool}, {"mode", "mode", serviceEnum("clamav", "icap")},
		{"fail-policy", "failPolicy", serviceEnum("open", "closed")}, {"max-size-bytes", "maxSizeBytes", serviceInt(0, 1<<63-1)},
		{"timeout-sec", "timeoutSec", serviceInt(0, 1<<31-1)}, {"cache-ttl", "cacheTtl", serviceDuration},
		{"http-download", "httpDownload", serviceBool}, {"http-upload", "httpUpload", serviceBool},
	})
	registerServiceFields(r, api, "av clamav", av, []serviceField{
		{"socket-path", "clamav.socketPath", serviceText}, {"update-schedule", "clamav.updateSchedule", serviceText},
		{"custom-defs-path", "clamav.customDefsPath", serviceText}, {"freshclam-enabled", "clamav.freshclamEnabled", serviceBool},
	})
	r.RegisterRole("set av icap server", RoleAdmin, setServiceICAPServer(api))
	registerServiceFields(r, api, "av scan", av, []serviceField{
		{"download-mode", "scan.downloadMode", serviceEnum("hold", "stream_tail")},
		{"ics-zones", "scan.icsZones", serviceList}, {"ics-assets", "scan.icsAssets", serviceList},
	})
	selection := []serviceField{
		{"source-zones", "sourceZones", serviceList}, {"dest-zones", "destZones", serviceList}, {"dest-ports", "destPorts", serviceList},
	}
	registerServiceCollection(r, api, serviceCollection{
		name: "av scan include", endpoint: av, path: "scan.include", fields: selection, required: []string{"dest-ports"},
	})
	registerServiceCollection(r, api, serviceCollection{
		name: "av scan exclude", endpoint: av, path: "scan.exclude", fields: append(selection[:len(selection):len(selection)],
			serviceField{"sources", "sources", serviceList}, serviceField{"destinations", "destinations", serviceList}),
	})
}
func setServiceICAPServer(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 3 {
			return fmt.Errorf("usage: set av icap server <host:port> <true|false TLS> <service>")
		}
		tls, err := serviceBool(args[1])
		if err != nil {
			return err
		}
		server := map[string]any{"address": args[0], "useTls": tls, "service": args[2]}
		return editService(api, "/api/v1/services/av", func(o serviceObject) error {
			return o.put("icap.servers", []any{server})
		})(ctx, out, nil)
	}
}
