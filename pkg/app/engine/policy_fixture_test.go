// SPDX-License-Identifier: Apache-2.0

package engineapp

import "context"

// In-process nft fakes have no kernel conntrack table.
func noPolicyMarks(context.Context, uint32, uint32, uint32) (int, error) { return 0, nil }
