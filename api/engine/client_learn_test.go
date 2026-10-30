// SPDX-License-Identifier: Apache-2.0
package engineapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEvidenceClientPreservesDomainFailures(t *testing.T) {
	for _, status := range []int{400, 404, 409, 410, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Error(err)
				}
				http.Error(w, "domain failure", status)
			}))
			defer server.Close()
			_, err := NewHTTPClient(server.URL).Learn(context.Background(), "GET", "/learn/datasets", "", nil)
			var domain *EvidenceError
			if !errors.As(err, &domain) || domain.Status != status {
				t.Fatalf("lost status: %v", err)
			}
		})
	}
}
