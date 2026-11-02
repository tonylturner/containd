// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"io"

	"github.com/peterh/liner"
	"github.com/tonylturner/containd/pkg/cli"
)

func cliSecretContext(ctx context.Context, interactive bool, prompt cli.SecretPrompt) context.Context {
	if !interactive {
		// In redirected mode liner can fall back to its ordinary echoed reader.
		return cli.WithSecretPrompt(ctx, nil)
	}
	return cli.WithSecretPrompt(ctx, func(label string) (string, error) {
		value, err := prompt(label)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, liner.ErrPromptAborted) {
			// Redirected output or an unsupported terminal cannot safely
			// provide liner's password reader. Never retry with plain input.
			return "", cli.ErrSecretInputUnavailable
		}
		return value, err
	})
}
