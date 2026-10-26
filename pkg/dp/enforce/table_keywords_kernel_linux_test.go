// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestKernelNFTRejectsKeywordTableNames checks the keyword list against the
// nft in this container, version 1.1.1 or later: each nft 1.1.1 keyword is a
// syntax error as an inet table name, and each keyword in capitals, which
// ValidateTableName accepts, is not. Keywords of later releases are checked
// in capitals only, since an older nft accepts them. It runs with the other
// kernel tests (see newNetnsLab).
func TestKernelNFTRejectsKeywordTableNames(t *testing.T) {
	if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires CONTAIND_NETNS_KERNEL_TEST=1 in a disposable privileged Linux container with nft")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	check := func(name string) error {
		cmd := exec.CommandContext(ctx, "nft", "-c", "-f", "-")
		cmd.Stdin = strings.NewReader(fmt.Sprintf("add table inet %s\n", name))
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, out)
		}
		return nil
	}
	if err := check("containd"); err != nil {
		t.Fatalf("nft check unusable: %v", err)
	}
	for _, w := range strings.Fields(nftKeywords111) {
		if check(w) == nil {
			t.Errorf("nft accepts keyword %q as a table name", w)
		}
	}
	for w := range nftKeywords {
		upper := strings.ToUpper(w)
		if err := ValidateTableName(upper); err != nil {
			t.Errorf("ValidateTableName(%q): %v", upper, err)
		} else if err := check(upper); err != nil {
			t.Errorf("nft rejects %q: %v", upper, err)
		}
	}
}
