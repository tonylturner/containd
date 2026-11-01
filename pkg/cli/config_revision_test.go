// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

type revisionClient struct {
	t               *testing.T
	counter         int
	requests        []string
	changeAfterRead bool
}

func (f *revisionClient) revision() string {
	return fmt.Sprintf("0123456789abcdef.%d", f.counter)
}

func (f *revisionClient) Do(r *http.Request) (*http.Response, error) {
	f.t.Helper()
	// Consume the body before recording; the same fake is usable by HTTP tests.
	if r.Body != nil {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			return nil, err
		}
	}
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	revision := f.revision()
	if r.Method == http.MethodGet {
		var body any = config.DefaultConfig()
		switch r.URL.Path {
		case "/api/v1/dataplane":
			body = config.DefaultConfig().DataPlane
		case "/api/v1/config/diff":
			body = map[string]any{"changes": []any{"reviewed edit"}}
		case "/api/v1/config/candidate":
		default:
			f.t.Fatalf("unexpected read: %s", r.URL.Path)
		}
		if f.changeAfterRead {
			f.counter++
		}
		return jsonHTTPResponse(200, body, map[string]string{"X-Containd-Revision": revision}), nil
	}
	if r.Header.Get("X-Containd-If-Revision") != revision {
		return jsonHTTPResponse(412, map[string]string{
			"error": "configuration changed since it was read", "code": "config_revision_mismatch", "currentRevision": revision,
		}, nil), nil
	}
	f.counter++
	return jsonHTTPResponse(200, map[string]string{"status": "committed"}, map[string]string{
		"X-Containd-Revision": f.revision(),
	}), nil
}

func TestCLIRevisionRMWConflictDoesNotRefreshOrRetry(t *testing.T) {
	client := &revisionClient{t: t, counter: 7, changeAfterRead: true}
	api := &API{BaseURL: "http://test", Client: client}
	var out bytes.Buffer
	err := setDataPlaneAPI(api)(context.Background(), &out, []string{"enforcement", "off"})
	var failure *ConfigFailure
	if !errors.As(err, &failure) || failure.Status != 412 || failure.Code != "config_revision_mismatch" ||
		string(failure.CurrentRevision) != client.revision() || out.Len() != 0 {
		t.Fatalf("conflict = %#v; error=%v output=%q", failure, err, &out)
	}
	if want := []string{"GET /api/v1/dataplane", "POST /api/v1/dataplane"}; !reflect.DeepEqual(client.requests, want) {
		t.Fatalf("requests=%v want=%v", client.requests, want)
	}
	if client.counter != 8 {
		t.Fatal("rejected edit changed configuration")
	}
}

func TestCLIRevisionLifecycleReadsCandidateWithinEachCommand(t *testing.T) {
	for _, name := range []string{"commit", "commit confirmed", "rollback", "confirm"} {
		t.Run(name, func(t *testing.T) {
			client := &revisionClient{t: t, counter: 10}
			api := &API{BaseURL: "http://test", Client: client}
			registry := NewRegistry(nil, api)
			for range 2 {
				client.counter++ // Another operator edits between commands.
				if err := registry.ParseAndExecute(WithRole(context.Background(), "admin"), name, io.Discard); err != nil {
					t.Fatal(err)
				}
			}
			if len(client.requests) != 4 || client.requests[0] != "GET /api/v1/config/candidate" ||
				client.requests[2] != "GET /api/v1/config/candidate" {
				t.Fatalf("not command-local Junos semantics: %v", client.requests)
			}
		})
	}
}

func TestCLIRevisionReviewedCommitDoesNotReadNewBase(t *testing.T) {
	client := &revisionClient{t: t, counter: 12}
	api := &API{BaseURL: "http://test", Client: client}
	registry := NewRegistry(nil, api)
	ctx := WithRole(context.Background(), "admin")
	reviewed := client.revision()
	var diff bytes.Buffer
	if err := registry.ParseAndExecute(ctx, "show diff", &diff); err != nil || !strings.Contains(diff.String(), reviewed) {
		t.Fatalf("diff=%q err=%v", &diff, err)
	}
	client.counter++
	err := registry.ParseAndExecute(ctx, "commit revision "+reviewed, io.Discard)
	var failure *ConfigFailure
	if !errors.As(err, &failure) || failure.Status != 412 || len(client.requests) != 2 ||
		client.requests[1] != "POST /api/v1/config/commit" {
		t.Fatalf("reviewed commit silently refreshed: %v %v", err, client.requests)
	}
	// An explicit new review, rather than an automatic retry, can succeed.
	if err := registry.ParseAndExecute(ctx, "commit revision "+client.revision(), io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestCLIRevisionReadsRejectMissingAuthority(t *testing.T) {
	for _, revision := range []string{"", "*", "1"} {
		t.Run("revision="+revision, func(t *testing.T) {
			client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
				"GET /api/v1/dataplane": func(*http.Request) (*http.Response, error) {
					return jsonHTTPResponse(200, config.DataPlaneConfig{}, map[string]string{"X-Containd-Revision": revision}), nil
				},
			}}
			api := &API{BaseURL: "http://test", Client: client}
			if err := setDataPlaneAPI(api)(context.Background(), io.Discard, []string{"enforcement", "off"}); err == nil {
				t.Fatal("write without an authoritative read")
			}
		})
	}
}

func TestCLIRevisionDirectIntentsEstablishCommandBase(t *testing.T) {
	for _, line := range []string{
		"set zone dmz", "assign interfaces auto", "add firewall rule allow ALLOW",
		"apply template modbus_read_only", "set syslog format json",
		"set port-forward add web wan tcp 8080 192.0.2.5:80",
		"delete firewall rule allow", "factory reset NUCLEAR",
		"apply learn suggestions receipt suggestion@1",
	} {
		t.Run(line, func(t *testing.T) {
			client := &revisionClient{t: t, counter: 30}
			registry := NewRegistry(nil, &API{BaseURL: "http://test", Client: client})
			if err := registry.ParseAndExecute(WithRole(context.Background(), "admin"), line, io.Discard); err != nil {
				t.Fatal(err)
			}
			if len(client.requests) != 2 || client.requests[0] != "GET /api/v1/config/candidate" || client.counter != 31 {
				t.Fatalf("direct intent did not use candidate authority: %v counter=%d", client.requests, client.counter)
			}
		})
	}
}

func TestCLIRevisionRequiredFailureAndMissingAcknowledgement(t *testing.T) {
	for _, status := range []int{200, 428} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
				"POST /api/v1/config/commit": func(r *http.Request) (*http.Response, error) {
					if _, err := io.Copy(io.Discard, r.Body); err != nil {
						t.Fatal(err)
					}
					calls++
					return jsonHTTPResponse(status, map[string]string{"code": "config_revision_required", "error": "revision required"},
						map[string]string{"X-Containd-Revision": ""}), nil
				},
			}}
			api := &API{BaseURL: "http://test", Client: client}
			var out bytes.Buffer
			err := api.saveJSON(context.Background(), "/api/v1/config/commit", nil, config.Revision("0123456789abcdef.1"), &out)
			if err == nil || calls != 1 || out.Len() != 0 {
				t.Fatalf("unacknowledged mutation: %v calls=%d output=%q", err, calls, &out)
			}
			if status == 428 {
				var failure *ConfigFailure
				if !errors.As(err, &failure) || failure.Status != status || failure.Code != "config_revision_required" {
					t.Fatalf("precondition details lost: %v", err)
				}
			}
		})
	}
}
