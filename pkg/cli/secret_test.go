// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestConfirmedPassword(t *testing.T) {
	for _, tc := range []struct {
		name, first, second, wantError string
		readError                      error
		wantCalls                      int
	}{
		{"exact", "  Pässword1 \t", "  Pässword1 \t", "", nil, 2},
		{"mismatch", " Password1 ", "Password1", "passwords do not match", nil, 2},
		{"blank", "", "", "cancelled", nil, 1},
		{"reader failure", "Secret1", "", "cancelled", errors.New("Secret1"), 1},
		{"web", "", "", ErrWebSecretInput.Error(), ErrWebSecretInput, 1},
		{"unavailable", "", "", ErrSecretInputUnavailable.Error(), ErrSecretInputUnavailable, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			ctx := WithSecretPrompt(context.Background(), func(label string) (string, error) {
				calls++
				if !strings.Contains(label, "immediate") {
					t.Fatalf("prompt does not explain immediacy: %s", label)
				}
				if calls == 1 {
					return tc.first, tc.readError
				}
				return tc.second, nil
			})
			got, err := confirmedPassword(ctx)
			if calls != tc.wantCalls {
				t.Fatalf("prompt calls = %d", calls)
			}
			if tc.wantError == "" {
				if err != nil || got != tc.first {
					t.Fatal("password was changed or refused")
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantError) || got != "" {
				t.Fatalf("expected refusal %q, got %v", tc.wantError, err)
			}
		})
	}
}

func TestSecretInputCapabilityBoundaries(t *testing.T) {
	calls := 0
	parent := WithSecretPrompt(context.Background(), func(string) (string, error) {
		calls++
		return "Password1", nil
	})
	for _, ctx := range []context.Context{context.Background(), WithSecretPrompt(parent, nil)} {
		if _, err := confirmedPassword(ctx); !errors.Is(err, ErrSecretInputUnavailable) {
			t.Fatalf("missing capability: %v", err)
		}
	}
	cancelled, cancel := context.WithCancel(parent)
	cancel()
	if _, err := confirmedPassword(cancelled); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("cancelled context read input: calls=%d err=%v", calls, err)
	}
	during, cancelDuring := context.WithCancel(context.Background())
	defer cancelDuring()
	during = WithSecretPrompt(during, func(string) (string, error) {
		cancelDuring()
		return "Password1", nil
	})
	if _, err := confirmedPassword(during); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled during read: %v", err)
	}
}
