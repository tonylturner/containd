package cli

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/containd/containd/pkg/cp/config"
)

func showRunningConfig(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var cfg config.Config
		if err := api.getJSON(ctx, "/api/v1/config/export", &cfg); err != nil {
			return err
		}
		return printJSON(out, cfg)
	}
}

func showCandidateConfig(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var cfg config.Config
		if err := api.getJSON(ctx, "/api/v1/config/candidate", &cfg); err != nil {
			return err
		}
		return printJSON(out, cfg)
	}
}

func showDiff(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var payload map[string]any
		if err := api.getJSON(ctx, "/api/v1/config/diff", &payload); err != nil {
			return err
		}
		return printJSON(out, payload)
	}
}

func showSystem(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		type health struct {
			Status    string `json:"status"`
			Component string `json:"component"`
			Build     string `json:"build,omitempty"`
			Time      string `json:"time,omitempty"`
		}
		var h health
		_ = api.getJSON(ctx, "/api/v1/health", &h)

		var cfg config.Config
		_ = api.getJSON(ctx, "/api/v1/config", &cfg)

		fmt.Fprintf(out, "hostname: %s\n", cfg.System.Hostname)
		fmt.Fprintf(out, "component: %s\n", h.Component)
		if h.Build != "" {
			fmt.Fprintf(out, "build: %s\n", h.Build)
		}
		if h.Time != "" {
			if t, err := time.Parse(time.RFC3339Nano, h.Time); err == nil {
				fmt.Fprintf(out, "time: %s\n", t.UTC().Format(time.RFC3339Nano))
			} else {
				fmt.Fprintf(out, "time: %s\n", h.Time)
			}
		}
		return nil
	}
}

func setSystemHostnameAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: set system hostname <name>")
		}
		cfg, err := loadCandidateOrRunning(ctx, api)
		if err != nil {
			return err
		}
		cfg.System.Hostname = args[0]
		return api.postJSON(ctx, "/api/v1/config/candidate", cfg, out)
	}
}

func setSystemMgmtListenAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: set system mgmt listen <addr>")
		}
		cfg, err := loadCandidateOrRunning(ctx, api)
		if err != nil {
			return err
		}
		cfg.System.Mgmt.ListenAddr = args[0]
		return api.postJSON(ctx, "/api/v1/config/candidate", cfg, out)
	}
}

func showIDSRulesAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var idsCfg config.IDSConfig
		if err := api.getJSON(ctx, "/api/v1/ids/rules", &idsCfg); err != nil {
			return err
		}
		return printJSON(out, idsCfg)
	}
}

func loadCandidateOrRunning(ctx context.Context, api *API) (*config.Config, error) {
	var cfg config.Config
	if err := api.getJSON(ctx, "/api/v1/config/candidate", &cfg); err == nil {
		return &cfg, nil
	}
	if err := api.getJSON(ctx, "/api/v1/config", &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

