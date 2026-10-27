// SPDX-License-Identifier: Apache-2.0
package sshserver

import (
	"fmt"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Session channels multiplexed on one connection run CLI commands
// concurrently without sharing CLI client state. Management refreshes the
// token in every response here, which a shared client would record from
// both channels at once.
func TestConcurrentChannelsOnOneConnection(t *testing.T) {
	srv, store, _ := newAssuranceServer(t)
	srv.opts.APIClient = &shellAPIUpstream{}
	addr := serveSSH(t, srv)
	u, password := createAdmin(t, store, "channels-admin")
	client, err := dialSSH(addr, u.Username, nil, ssh.Password(password))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer client.Close()

	const channels, commands = 2, 10
	start := make(chan struct{})
	errs := make(chan error, channels*commands)
	var wg sync.WaitGroup
	for i := 0; i < channels; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < commands; j++ {
				session, err := client.NewSession()
				if err != nil {
					errs <- err
					return
				}
				out, err := session.CombinedOutput("show health")
				_ = session.Close()
				if err != nil {
					errs <- fmt.Errorf("show health: %v: %s", err, out)
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
