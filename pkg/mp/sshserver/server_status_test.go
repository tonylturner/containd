// SPDX-License-Identifier: Apache-2.0
package sshserver

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cli"
)

type statusOutput struct {
	mu sync.Mutex
	bytes.Buffer
	prompt chan struct{}
	once   sync.Once
}

func (b *statusOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, err := b.Buffer.Write(p)
	if b.prompt != nil && strings.Contains(b.Buffer.String(), "containd(config?)#") {
		b.once.Do(func() { close(b.prompt) })
	}
	return n, err
}

func (b *statusOutput) text() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

func TestSSHStatusRequestDoesNotBlockCommands(t *testing.T) {
	srv, _, _ := newTestSSHServer(t)
	started, release, command, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var startedOnce, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	client := secretHTTPClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/api/v1/config/diff" {
			startedOnce.Do(func() { close(started) })
			// Deliberately hold HTTP until the command has run, independent
			// of wall-clock scheduling. The timeout itself is tested in cli.
			<-release
			return jsonResponse(200, map[string]bool{"changed": false}), nil
		}
		return jsonResponse(200, map[string]string{"username": "admin", "role": "admin"}), nil
	})
	srv.opts.APIClient = client
	reg := cli.NewRegistry(nil, nil)
	reg.Register("note completed", func(context.Context, io.Writer, []string) error {
		close(command)
		return nil
	})
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	input := newSessionInput(reader)
	defer input.close()
	output := &statusOutput{prompt: make(chan struct{})}
	go func() {
		defer close(done)
		srv.repl(cli.WithRole(context.Background(), "admin"), "admin", "test", reg,
			&sessionIO{sessionInput: input, Writer: output}, nil, nil)
	}()
	await := func(ch <-chan struct{}, label string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s blocked", label)
		}
	}
	await(started, "status request")
	await(output.prompt, "initial unknown prompt")
	if !strings.Contains(output.text(), "containd(config?)#") {
		t.Fatal("unknown prompt was not displayed while refreshing")
	}
	go func() { _, _ = io.WriteString(writer, "note completed\nexit\n") }()
	await(command, "command behind a pending status request")
	unblock()
	await(done, "session shutdown")
	if !strings.Contains(output.text(), cli.SessionExit) {
		t.Fatal("exit banner missing")
	}
}
