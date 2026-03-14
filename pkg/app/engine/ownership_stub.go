// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package engineapp

import (
	"context"

	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/cp/config"
)

type ownershipManager struct{}

func newOwnershipManager(logger *zap.SugaredLogger) *ownershipManager { return &ownershipManager{} }
func (m *ownershipManager) setInterfaces(_ []config.Interface)        {}
func (m *ownershipManager) setRouting(_ config.RoutingConfig)         {}
func (m *ownershipManager) start(_ context.Context)                   {}
func (m *ownershipManager) currentInterfaces() []config.Interface     { return nil }
func ownershipStatus(_ *ownershipManager) map[string]any              { return map[string]any{"enabled": false} }
