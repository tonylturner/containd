// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ICMP rows show the identifier and the type and code where TCP and UDP rows
// show ports.
func TestShowConntrackICMPColumns(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/conntrack" || r.URL.Query().Get("limit") != "200" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
{"proto":"tcp","state":"ESTABLISHED","src":"192.0.2.1","dst":"192.0.2.2","sport":"41000","dport":"502"},
{"proto":"icmp","src":"192.0.2.1","dst":"192.0.2.3","icmpId":"4660","icmpType":"8","icmpCode":"0"},
{"proto":"icmpv6","src":"2001:db8::1","dst":"2001:db8::2","icmpId":"0","icmpType":"128","icmpCode":"0"}]`))
	}))
	defer server.Close()
	var out bytes.Buffer
	if err := showConntrackAPI(&API{BaseURL: server.URL})(context.Background(), &out, nil); err != nil {
		t.Fatal(err)
	}
	rows := map[string][]string{}
	for _, line := range strings.Split(out.String(), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 {
			rows[fields[0]] = fields
		}
	}
	for proto, want := range map[string]string{
		"tcp":    "tcp ESTABLISHED 192.0.2.1 41000 192.0.2.2 502",
		"icmp":   "icmp — 192.0.2.1 id 4660 192.0.2.3 type 8/0",
		"icmpv6": "icmpv6 — 2001:db8::1 id 0 2001:db8::2 type 128/0",
	} {
		if got := strings.Join(rows[proto], " "); !strings.HasPrefix(got, want+" ") {
			t.Fatalf("%s row %q, want prefix %q\n%s", proto, got, want, out.String())
		}
	}
}
