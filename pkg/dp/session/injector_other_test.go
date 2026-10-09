// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package session

import (
	"errors"
	"testing"
)

func TestNewInjectorUnsupported(t *testing.T) {
	inj, err := NewInjector()
	if !errors.Is(err, ErrUnsupportedPlatform) || inj != nil {
		t.Fatalf("NewInjector = %v, %v; want nil, ErrUnsupportedPlatform", inj, err)
	}
}
