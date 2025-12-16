//go:build !linux

package cli

import (
	"context"
	"fmt"
	"io"
)

func showNeighbors() Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		return fmt.Errorf("show neighbors is only supported on Linux (run inside the containd container/appliance)")
	}
}

