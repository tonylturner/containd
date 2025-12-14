//go:build !linux

package main

import (
	"context"
	"log"

	"github.com/containd/containd/pkg/cp/config"
)

type ownershipManager struct{}

func newOwnershipManager(logger *log.Logger) *ownershipManager    { return &ownershipManager{} }
func (m *ownershipManager) setInterfaces(_ []config.Interface)    {}
func (m *ownershipManager) setRouting(_ config.RoutingConfig)     {}
func (m *ownershipManager) start(_ context.Context)               {}
func (m *ownershipManager) currentInterfaces() []config.Interface { return nil }
func ownershipStatusJSON(_ *ownershipManager) []byte              { return []byte(`{"enabled":false}`) }
