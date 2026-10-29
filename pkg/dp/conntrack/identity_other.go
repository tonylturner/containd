// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package conntrack

import (
	"context"
	"fmt"
)

type identityReader struct{}

func NewIdentityReader() IdentityReader { return &identityReader{} }
func (*identityReader) Close() error    { return nil }
func (*identityReader) Lookup(context.Context, Tuple) (Evidence, error) {
	return Evidence{}, fmt.Errorf("conntrack identity requires Linux")
}
