// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
)

// ClearBlocks removes every temporary host and flow block. Blocks otherwise
// outlive ruleset applies and engine restarts until their timeouts expire.
// Without enforcement the engine owns no blocks table: there is nothing to
// clear.
func (e *Engine) ClearBlocks(ctx context.Context) error {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	if e.compiler == nil {
		return nil
	}
	if e.applier == nil {
		return errors.New("no applier configured")
	}
	return e.applier.Apply(ctx, e.compiler.ClearBlocks())
}
