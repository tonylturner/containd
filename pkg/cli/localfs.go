// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"errors"
	"io"
)

var ErrLocalFilesystemUnavailable = errors.New("file arguments require the local containd cli or SSH appliance CLI; the web console cannot read or write appliance files")

type localFilesystemKey struct{}

// WithLocalFilesystem grants session-scoped access to caller-supplied paths.
// Only local CLI and SSH transports grant it. Web transports explicitly revoke
// it, including any inherited capability. It does not grant an admin role.
func WithLocalFilesystem(ctx context.Context, allowed bool) context.Context {
	return context.WithValue(ctx, localFilesystemKey{}, allowed)
}

func requireLocalFilesystem(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if allowed, _ := ctx.Value(localFilesystemKey{}).(bool); !allowed {
		return ErrLocalFilesystemUnavailable
	}
	return nil
}

func localFilesystemCommand(command Command) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if err := requireLocalFilesystem(ctx); err != nil {
			return err
		}
		return command(ctx, out, args)
	}
}
