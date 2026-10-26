// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

//go:build !linux

package engine

import "context"

// watch has no interface change notifications to subscribe to on this
// platform: the cache reads the interfaces on every lookup.
func (c *zoneCache) watch(context.Context, func(error)) {}
