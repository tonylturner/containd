// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/tonylturner/containd/pkg/dp/signatures"
)

// showSignaturesAPI lists all loaded ICS signatures.
func showSignaturesAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var sigs []signatures.Signature
		if err := api.getJSON(ctx, "/api/v1/signatures", &sigs); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		if len(sigs) == 0 {
			fmt.Fprintln(out, "No signatures loaded.")
			return nil
		}
		t := newTable("ID", "NAME", "SEVERITY", "PROTOCOL", "CONDITIONS", "REFERENCES")
		for _, s := range sigs {
			t.addRow(
				s.ID,
				truncate(s.Name, 30),
				s.Severity,
				firstNonEmpty(s.Protocol, "any"),
				fmt.Sprintf("%d", len(s.Conditions)),
				joinCSV(s.References),
			)
		}
		t.render(out)
		return nil
	}
}

// showSignatureMatchesAPI lists recent signature matches.
func showSignatureMatchesAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var matches []signatures.Match
		if err := api.getJSON(ctx, "/api/v1/signatures/matches?limit=100", &matches); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		if len(matches) == 0 {
			fmt.Fprintln(out, "No signature matches.")
			return nil
		}
		t := newTable("TIME", "SIG_ID", "NAME", "SEVERITY", "PROTO", "KIND")
		for _, m := range matches {
			t.addRow(
				fmtTime(m.Timestamp),
				m.Signature.ID,
				truncate(m.Signature.Name, 30),
				m.Signature.Severity,
				m.Event.Proto,
				m.Event.Kind,
			)
		}
		t.render(out)
		return nil
	}
}
