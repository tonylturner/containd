// SPDX-License-Identifier: Apache-2.0

package sshserver

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// promptInput rejects reads of later input before the next prompt. This
// catches blocking lookahead without relying on goroutines or timeouts.
type promptInput struct {
	chunks  []string
	allowed bool
}

func (r *promptInput) Read(p []byte) (int, error) {
	if !r.allowed {
		return 0, errors.New("read ahead before next prompt")
	}
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	r.chunks[0] = r.chunks[0][n:]
	if r.chunks[0] == "" {
		r.chunks = r.chunks[1:]
		r.allowed = false
	}
	return n, nil
}

func TestTerminalLineEndings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		chunks []string
		want   []string
	}{
		{"CR", []string{"one\r", "secret\r", "three\r"}, []string{"one", "secret", "three"}},
		{"LF", []string{"one\n", "secret\n", "three\n"}, []string{"one", "secret", "three"}},
		{"CRLF", []string{"one\r\n", "secret\r\n", "three\r\n"}, []string{"one", "secret", "three"}},
		{"split CRLF", []string{"one\r", "\nsecret\r", "\nthree\r"}, []string{"one", "secret", "three"}},
		{"empty CR", []string{"\r", "\r", "three\r"}, []string{"", "", "three"}},
		{"empty LF", []string{"\n", "\n", "three\n"}, []string{"", "", "three"}},
		{"empty CRLF", []string{"\r\n", "\r\n", "three\r\n"}, []string{"", "", "three"}},
		{"preserve second LF", []string{"one\r\n\n", "three\n"}, []string{"one", "", "three"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := &promptInput{chunks: append([]string(nil), tc.chunks...)}
			reader := bufio.NewReader(input)
			var out bytes.Buffer
			for i, want := range tc.want {
				input.allowed = true
				var got string
				var ok bool
				if i == 1 {
					got, ok = readSecretInteractive(reader, &out)
				} else {
					got, ok = readLineInteractive(reader, &out)
				}
				if !ok || got != want {
					t.Fatalf("line %d = %q, %v; want %q, true", i, got, ok, want)
				}
			}
			wantOut := tc.want[0] + "\r\n\r\n" + tc.want[2] + "\r\n"
			if out.String() != wantOut || strings.Contains(out.String(), "secret") {
				t.Fatalf("output = %q; want %q", out.String(), wantOut)
			}
		})
	}
}
