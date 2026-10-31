// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	engineapi "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/common/enginetransport"
)

func TestManagementGuardSharedTransport(t *testing.T) {
	secret := hex.EncodeToString([]byte("public engine transport test key"))
	t.Setenv("CONTAIND_ENGINE_SECRET", secret)
	b, _ := enginetransport.Secret()
	identity, err := enginetransport.Derive(b)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			t.Error("guard bypassed TLS")
		}
		_, _ = io.WriteString(w, `{"managementReservation":{"active":true}}`)
	}))
	srv.TLS = identity.ServerTLS()
	srv.StartTLS()
	defer srv.Close()
	target, err := enginetransport.Resolve(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := engineapi.NewHTTPClientForTarget(target)
	defer client.Client.CloseIdleConnections()
	// Changing the environment after startup cannot change this transport.
	t.Setenv("CONTAIND_ENGINE_SECRET", "invalid")
	health, err := managementGuardHealth(client)(context.Background())
	if err != nil || !health.Active {
		t.Fatalf("health=%+v err=%v", health, err)
	}
}
