// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// learnedProfileJSON mirrors learn.LearnedProfile for JSON decoding in the CLI.
type learnedProfileJSON struct {
	Protocol      string          `json:"protocol"`
	SourceIP      string          `json:"sourceIP"`
	DestIP        string          `json:"destIP"`
	UnitIDs       map[string]bool `json:"unitIDs"`
	FunctionCodes map[string]bool `json:"functionCodes"`
	Addresses     map[string]bool `json:"addresses"`
	ReadSeen      bool            `json:"readSeen"`
	WriteSeen     bool            `json:"writeSeen"`
	FirstSeen     string          `json:"firstSeen"`
	LastSeen      string          `json:"lastSeen"`
	PacketCount   int             `json:"packetCount"`
}

func showLearnProfiles(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var profiles []learnedProfileJSON
		if err := api.getJSON(ctx, "/api/v1/learn/profiles", &profiles); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		if len(profiles) == 0 {
			fmt.Fprintln(out, "No learned profiles.")
			return nil
		}
		t := newTable("PROTOCOL", "SOURCE", "DEST", "FUNC_CODES", "UNIT_IDS", "ADDRS", "RW", "PACKETS", "FIRST", "LAST")
		for _, p := range profiles {
			rw := "rw"
			if p.ReadSeen && !p.WriteSeen {
				rw = "ro"
			} else if p.WriteSeen && !p.ReadSeen {
				rw = "wo"
			}
			t.addRow(
				p.Protocol,
				p.SourceIP,
				p.DestIP,
				truncate(joinMapKeys(p.FunctionCodes), 20),
				truncate(joinMapKeys(p.UnitIDs), 12),
				truncate(joinMapKeys(p.Addresses), 24),
				rw,
				fmt.Sprintf("%d", p.PacketCount),
				truncate(p.FirstSeen, 19),
				truncate(p.LastSeen, 19),
			)
		}
		t.render(out)
		return nil
	}
}

func showLearnRules(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		rules, err := postAndDecodeRules(ctx, api, "/api/v1/learn/generate")
		if err != nil {
			return err
		}
		return renderLearnRules(out, rules)
	}
}

func postAndDecodeRules(ctx context.Context, api *API, path string) ([]config.Rule, error) {
	if api.Client == nil {
		api.Client = defaultHTTPClient
	}
	body := &bytes.Buffer{}
	_ = json.NewEncoder(body).Encode(map[string]any{})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if api.Token != "" {
		req.Header.Set("Authorization", "Bearer "+api.Token)
	}
	resp, err := api.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	api.updateTokenFromResponse(resp)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	var rules []config.Rule
	if err := json.NewDecoder(resp.Body).Decode(&rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func renderLearnRules(out io.Writer, rules []config.Rule) error {
	if out == nil {
		return nil
	}
	if len(rules) == 0 {
		fmt.Fprintln(out, "No rules generated (no learned traffic).")
		return nil
	}
	fmt.Fprintf(out, "Generated %d rule(s):\n\n", len(rules))
	t := newTable("ID", "ACTION", "SRC", "DST", "PROTO", "FUNC_CODES", "MODE")
	for _, r := range rules {
		fcs := make([]string, 0, len(r.ICS.FunctionCode))
		for _, fc := range r.ICS.FunctionCode {
			fcs = append(fcs, fmt.Sprintf("%d", fc))
		}
		t.addRow(
			r.ID,
			string(r.Action),
			joinCSV(r.Sources),
			joinCSV(r.Destinations),
			r.ICS.Protocol,
			strings.Join(fcs, ","),
			r.ICS.Mode,
		)
	}
	t.render(out)
	return nil
}

func applyLearnRules(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		return api.postJSON(ctx, "/api/v1/learn/apply", map[string]any{}, out)
	}
}

func clearLearnData(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		return api.delete(ctx, "/api/v1/learn", out)
	}
}

func joinMapKeys(m map[string]bool) string {
	if len(m) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return strings.Join(keys, ",")
}
