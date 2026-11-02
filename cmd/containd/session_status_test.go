// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cli"
)

func TestLocalStatusRequestDoesNotBlockInput(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	api := &cli.API{BaseURL: "http://management", Client: secretTestClient(func(*http.Request) (*http.Response, error) {
		once.Do(func() { close(started) })
		<-release
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	p := cli.NewSessionStatusPoller(context.Background(), api)
	defer p.Close()
	defer close(release)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("status request never started")
	}
	reads := 0
	var output strings.Builder
	err := runCLILoop("", func(string) (string, error) {
		reads++
		if p.Snapshot().Prompt("admin") != "containd(config?)# " {
			t.Fatal("pending status presented as authoritative")
		}
		if reads == 1 {
			return "show version", nil
		}
		return "exit", nil
	}, func(string) {}, func(line string, out *strings.Builder) error {
		return cli.NewRegistry(nil, nil).ParseAndExecute(context.Background(), line, out)
	}, true, &output, &output)
	if err != nil || reads != 2 || !strings.Contains(output.String(), "containd") {
		t.Fatalf("input waited for status: reads=%d err=%v", reads, err)
	}
}
