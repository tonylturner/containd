// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"errors"
)

var (
	ErrSecretInputUnavailable = errors.New("password input requires an interactive local or SSH terminal; piped sessions do not take secret input")
	ErrWebSecretInput         = errors.New("Set passwords on System → Users; the web console does not take secret input") //nolint:staticcheck // ST1005: verbatim user-facing web console guidance.
	ErrSecretInputCancelled   = errors.New("password entry cancelled; no account change requested")
)

// SecretPrompt reads one untrimmed, unechoed value. Transports must never send
// that value through command parsing, command history, logging or auditing.
type SecretPrompt func(prompt string) (string, error)

type secretPromptKey struct{}

// WithSecretPrompt supplies a session-scoped input capability, not a credential.
// A nil prompt deliberately disables secret input, including inherited readers.
func WithSecretPrompt(ctx context.Context, prompt SecretPrompt) context.Context {
	return context.WithValue(ctx, secretPromptKey{}, prompt)
}

// RefuseWebSecretInput is the web transport's explicit refusal capability.
func RefuseWebSecretInput(string) (string, error) {
	return "", ErrWebSecretInput
}

// confirmedPassword never trims input and never includes values or reader errors
// in its errors. A blank first entry cancels, like the SSH menu password flow.
func confirmedPassword(ctx context.Context) (string, error) {
	prompt, _ := ctx.Value(secretPromptKey{}).(SecretPrompt)
	if prompt == nil {
		return "", ErrSecretInputUnavailable
	}
	read := func(label string) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		value, err := prompt(label)
		if errors.Is(err, ErrWebSecretInput) {
			return "", ErrWebSecretInput
		}
		if errors.Is(err, ErrSecretInputUnavailable) {
			return "", ErrSecretInputUnavailable
		}
		if err != nil {
			return "", ErrSecretInputCancelled
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		return value, nil
	}
	password, err := read("New password (immediate operation; blank to cancel): ")
	if err != nil {
		return "", err
	}
	if password == "" {
		return "", ErrSecretInputCancelled
	}
	confirmation, err := read("Confirm new password (applies immediately): ")
	if err != nil {
		return "", err
	}
	if password != confirmation {
		return "", errors.New("passwords do not match; no account change requested")
	}
	return password, nil
}
