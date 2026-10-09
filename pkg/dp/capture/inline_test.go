// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package capture

import (
	"errors"
	"testing"
)

func TestTokenContract(t *testing.T) {
	var zero Token
	if zero.Inline() || zero.Generation() != 0 || zero.String() != "none" {
		t.Fatalf("zero token: inline=%v gen=%d str=%q", zero.Inline(), zero.Generation(), zero.String())
	}
	tok := NewToken(7, 42)
	if !tok.Inline() || tok.Generation() != 7 || tok.String() != "g7/42" {
		t.Fatalf("token: inline=%v gen=%d str=%q", tok.Inline(), tok.Generation(), tok.String())
	}
	held := map[Token]Verdict{tok: VerdictDrop}
	if held[NewToken(7, 42)] != VerdictDrop || len(held) != 1 {
		t.Fatal("tokens with equal generation and id must be equal map keys")
	}
	if NewToken(7, 42) == NewToken(8, 42) {
		t.Fatal("tokens of different generations must differ")
	}
}

func TestNewTokenRejectsGenerationZero(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewToken(0, id) must panic")
		}
	}()
	NewToken(0, 1)
}

func TestDecisionZeroValueIsAccept(t *testing.T) {
	var d Decision
	if d.Action != Accept || d.Reason != "" || d.Resolved != nil {
		t.Fatalf("zero Decision = %+v, want Accept", d)
	}
	if VerdictAccept == 0 || VerdictDrop == 0 || VerdictAccept == VerdictDrop {
		t.Fatal("verdicts must be non-zero and distinct")
	}
}

func TestSettlerRejectsUntilInline(t *testing.T) {
	inline := NewToken(1, 9)
	reqs := []Resolution{{Token: inline, Verdict: VerdictDrop}, {Token: Token{}, Verdict: VerdictAccept}}

	cases := []struct {
		name string
		cfg  Config
		want []error
	}{
		{"afpacket", Config{Interfaces: []string{"eth0"}}, []error{ErrNotInline, ErrNotInline}},
		{"empty", Config{}, []error{ErrNotInline, ErrNotInline}},
		{"nfqueue", Config{Mode: "NFQUEUE", QueueID: 100}, []error{ErrQueueClosed, ErrNotInline}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := NewManager(tc.cfg)
			if err != nil {
				t.Fatalf("NewManager: %v", err)
			}
			s := m.Settler()
			if s == nil || s != m.Settler() {
				t.Fatal("Settler must return a stable non-nil handle from construction")
			}
			errs := s.Settle(reqs...)
			if len(errs) != len(reqs) {
				t.Fatalf("Settle returned %d errors for %d requests", len(errs), len(reqs))
			}
			for i, want := range tc.want {
				if !errors.Is(errs[i], want) {
					t.Fatalf("request %d: err = %v, want %v", i, errs[i], want)
				}
			}
			if got := s.Settle(); len(got) != 0 {
				t.Fatalf("empty Settle = %v", got)
			}
		})
	}
}
