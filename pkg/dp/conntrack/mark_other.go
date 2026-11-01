// SPDX-License-Identifier: Apache-2.0
//go:build !linux

package conntrack

import (
	"context"
	"fmt"
)

func ClearMark(_ context.Context, _, _, _ uint32) (int, error) {
	return 0, fmt.Errorf("conntrack mark update is only available on Linux")
}
