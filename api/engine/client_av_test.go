// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAVClientMethods(t *testing.T) {
	var gotPath, gotQuery, gotBody, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotPath, gotQuery, gotBody, gotMethod = r.URL.Path, r.URL.RawQuery, string(body), r.Method
		switch r.URL.Path {
		case "/internal/av/status":
			_, _ = io.WriteString(w, `{"ready":true,"db_version":"ClamAV 1.5.2/1/x"}`)
		case "/internal/av/update":
			w.WriteHeader(http.StatusAccepted)
		case "/internal/av/defs":
			switch r.Method {
			case http.MethodGet:
				_, _ = io.WriteString(w, `{"path":"/data/clamav/custom","files":["a.ndb"],"definitions":[{"name":"a.ndb","active":true}]}`)
			case http.MethodPost:
				_, _ = io.WriteString(w, `{"name":"b.ndb","size":3,"active":true}`)
			default:
				_, _ = io.WriteString(w, `{"status":"deleted"}`)
			}
		}
	}))
	defer srv.Close()
	c := NewHTTPClient(srv.URL)
	ctx := context.Background()

	status, err := c.AVStatus(ctx)
	if err != nil || status["ready"] != true {
		t.Fatalf("AVStatus = %v, %v", status, err)
	}
	if err := c.TriggerAVUpdate(ctx); err != nil || gotMethod != http.MethodPost || gotPath != "/internal/av/update" {
		t.Fatalf("TriggerAVUpdate = %v (%s %s)", err, gotMethod, gotPath)
	}
	list, err := c.ListAVDefs(ctx)
	if err != nil || len(list.Definitions) != 1 || !list.Definitions[0].Active {
		t.Fatalf("ListAVDefs = %+v, %v", list, err)
	}
	def, err := c.UploadAVDef(ctx, "b c.ndb", strings.NewReader("abc"))
	if err != nil || def.Name != "b.ndb" || gotBody != "abc" || gotQuery != "name=b+c.ndb" {
		t.Fatalf("UploadAVDef = %+v, %v (query %q body %q)", def, err, gotQuery, gotBody)
	}
	if err := c.DeleteAVDef(ctx, "b.ndb"); err != nil || gotMethod != http.MethodDelete || gotQuery != "name=b.ndb" {
		t.Fatalf("DeleteAVDef = %v (%s %s)", err, gotMethod, gotQuery)
	}
}

func TestAVClientReportsStatusErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "av operation not available: freshclam already running", http.StatusConflict)
	}))
	defer srv.Close()
	err := NewHTTPClient(srv.URL).TriggerAVUpdate(context.Background())
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusConflict || !strings.Contains(se.Detail, "already running") {
		t.Fatalf("TriggerAVUpdate error = %#v", err)
	}
	if _, err := NewHTTPClient("").AVStatus(context.Background()); err == nil {
		t.Fatal("empty BaseURL accepted")
	}
}
