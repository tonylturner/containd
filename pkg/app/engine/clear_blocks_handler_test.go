// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/engine"
)

type scriptApplier struct {
	scripts []string
	err     error
}

func (a *scriptApplier) Apply(_ context.Context, script string) error {
	a.scripts = append(a.scripts, script)
	return a.err
}

func (a *scriptApplier) ReadTable(context.Context, string) (enforce.TableLayout, error) {
	return enforce.TableLayout{}, nil
}

func TestClearBlocksHandler(t *testing.T) {
	applier := &scriptApplier{}
	dp, err := engine.New(engine.Config{Enforce: engine.EnforceConfig{ClearMark: noPolicyMarks, Enabled: true, TableName: "fw", Applier: applier}})
	if err != nil {
		t.Fatal(err)
	}
	post := func(dp *engine.Engine, method string) int {
		rec := httptest.NewRecorder()
		clearBlocksHandler(dp).ServeHTTP(rec, httptest.NewRequest(method, "/internal/blocks/clear", nil))
		return rec.Code
	}
	want := enforce.NewCompilerWithSettings(enforce.CompilerSettings{TableName: "fw"}, nil).ClearBlocks()
	if code := post(dp, http.MethodPost); code != http.StatusOK || len(applier.scripts) != 1 || applier.scripts[0] != want {
		t.Fatalf("clear = %d, scripts %q", code, applier.scripts)
	}
	if code := post(dp, http.MethodGet); code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d", code)
	}
	applier.err = errors.New("nft: netlink busy")
	if code := post(dp, http.MethodPost); code != http.StatusBadGateway {
		t.Fatalf("failed clear = %d", code)
	}
	if code := post(nil, http.MethodPost); code != http.StatusServiceUnavailable {
		t.Fatalf("no engine = %d", code)
	}
}
