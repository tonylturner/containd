// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/users"
)

func TestProfilePatchPreservesOmissions(t *testing.T) {
	f := newAccountFixture(t)
	token, _ := f.session(t, f.adminID)
	for _, path := range []string{"/api/v1/auth/me", "/api/v1/users/" + f.adminID} {
		f.mustDo(t, http.MethodPatch, path, token, map[string]string{"firstName": "Ada", "lastName": "Lovelace", "email": "ada@example.com"})
		var got users.User
		body := f.mustDo(t, http.MethodPatch, path, token, map[string]string{"firstName": ""})
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		if got.FirstName != "" || got.LastName != "Lovelace" || got.Email != "ada@example.com" {
			t.Fatalf("patch %s: %+v", path, got)
		}
	}
}
