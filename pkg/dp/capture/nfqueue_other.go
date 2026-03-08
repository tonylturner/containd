// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package capture

import (
	"context"
	"errors"
)

func (m *Manager) startNFQueue(_ context.Context, _ Handler) error {
	return errors.New("nfqueue capture is only supported on linux")
}
