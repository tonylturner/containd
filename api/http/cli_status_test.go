// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/tonylturner/containd/pkg/cli"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestCLIStatusTracksOtherSessionsCandidateEdits(t *testing.T) {
	store := stageStore(t)
	store.SetSSHRuntimePolicyReader(func(context.Context) (config.SSHRuntimePolicy, error) {
		return config.SSHRuntimePolicy{
			ShellMode: config.SSHShellModeAppliance, ShellModeSource: config.SSHShellModeSourceDefault,
		}, nil
	})
	server := httptest.NewServer(NewServerWithEngine(store, nil, &stageEngine{mockEngine: &mockEngine{}}))
	defer server.Close()
	bindConsoleTest(t, config.ManagementListeners{HTTP: config.ManagementListener{
		Addr: server.Listener.Addr().String(), Enabled: true,
	}})
	ctx := cli.WithRole(context.Background(), "admin")
	api := &cli.API{BaseURL: server.URL, Client: server.Client(), Token: testAdminToken}
	otherSession := cli.NewRegistry(nil, api)
	execute := func(line string) {
		t.Helper()
		var output strings.Builder
		if err := otherSession.ParseAndExecute(ctx, line, &output); err != nil {
			t.Fatalf("%s: %v; output=%s", line, err, &output)
		}
	}
	execute("set system hostname confirmed-host")
	execute("commit confirmed 3600")

	ticketResponse := httptest.NewRecorder()
	server.Config.Handler.ServeHTTP(ticketResponse, authedRequest(http.MethodPost, "/api/v1/cli/ws/ticket", nil))
	conn, response, err := websocket.DefaultDialer.Dial(
		"ws"+strings.TrimPrefix(server.URL, "http")+"/api/v1/cli/ws?ticket="+decodeCLITicket(t, ticketResponse), nil)
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	type frame struct{ Output, Error, Prompt, Status string }
	readFrame := func(changed, pending bool) frame {
		t.Helper()
		var result frame
		if err := conn.ReadJSON(&result); err != nil {
			t.Fatal(err)
		}
		prompt, status := "containd(config)# ", "Candidate matches running"
		if changed {
			prompt, status = "containd(config*)# ", "Pending changes"
		}
		if result.Error != "" || result.Prompt != prompt || !strings.Contains(result.Status, status) ||
			strings.Contains(result.Status, "Confirmation pending until") != pending {
			t.Fatalf("incorrect console state: %+v", result)
		}
		return result
	}
	readDiff := func(changed, pending bool) config.Revision {
		t.Helper()
		resp, err := server.Client().Do(authedRequest(http.MethodGet, server.URL+"/api/v1/config/diff", nil))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var diff struct {
			Changed         bool
			ChangedSections []string
			PendingConfirm  *config.PendingConfirm
			Running         *config.Config
			Candidate       *config.Config
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("diff returned %d", resp.StatusCode)
		}
		if err := json.NewDecoder(resp.Body).Decode(&diff); err != nil {
			t.Fatal(err)
		}
		if diff.Changed != changed || (diff.PendingConfirm != nil) != pending {
			t.Fatalf("incorrect diff state: %+v", diff)
		}
		if changed {
			if !reflect.DeepEqual(diff.ChangedSections, []string{"system"}) ||
				diff.Running.System.Hostname != "confirmed-host" || diff.Candidate.System.Hostname != "other-session" {
				t.Fatalf("missing other session's edit: %+v", diff)
			}
		} else if len(diff.ChangedSections) != 0 || !reflect.DeepEqual(diff.Running, diff.Candidate) {
			t.Fatalf("clean diff contains changes: %+v", diff)
		}
		revision := config.Revision(resp.Header.Get(revisionHeader))
		if !revision.Valid() {
			t.Fatal("diff has no valid revision")
		}
		return revision
	}
	showSystem := func(changed, pending bool) {
		t.Helper()
		before := readDiff(changed, pending)
		if err := conn.WriteJSON(map[string]string{"line": "show system"}); err != nil {
			t.Fatal(err)
		}
		result := readFrame(changed, pending)
		// Command output names running configuration, whereas the prompt names
		// the shared candidate. A dirty prompt is not evidence of a write.
		if !strings.Contains(result.Output, "hostname: confirmed-host\n") ||
			strings.Contains(result.Output, "other-session") {
			t.Fatalf("show system did not read running configuration: %+v", result)
		}
		if after := readDiff(changed, pending); after != before {
			t.Fatalf("read-only console command changed revision: %s -> %s", before, after)
		}
	}

	// A pending confirmation is independent of staged edits: promotion is
	// already clean both before and after confirming its rollback timer.
	readFrame(false, true)
	showSystem(false, true)
	execute("confirm")
	showSystem(false, false)

	// Another session edits between this console's read-only commands.
	// The prompt must follow that actual shared-candidate transition.
	execute("set system hostname other-session")
	showSystem(true, false)
	execute("set system hostname confirmed-host")
	showSystem(false, false)
}
