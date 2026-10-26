// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConntrackKillRejectsInvalidInput(t *testing.T) {
	for _, body := range []string{`{`, `{"proto":"tcp","src":"192.0.2.1","dst":"2001:db8::1","sport":1234,"dport":443}`, `{"proto":"tcp","src":"192.0.2.1","dst":"192.0.2.2","sport":1234,"dport":443,"scope":"host"}`} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/internal/conntrack", bytes.NewBufferString(body))
		conntrackHandler(nil).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), "deleted") {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
	}
}
