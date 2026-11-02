// SPDX-License-Identifier: Apache-2.0
package sshserver

import (
	"context"

	"github.com/tonylturner/containd/pkg/cli"
)

func (s *interactiveSession) secretContext(interactive bool) context.Context {
	if !interactive {
		return cli.WithSecretPrompt(s.ctx, nil)
	}
	return cli.WithSecretPrompt(s.ctx, func(prompt string) (string, error) {
		value, ok := s.askSecret(prompt)
		if !ok {
			return "", cli.ErrSecretInputCancelled
		}
		return value, nil
	})
}
