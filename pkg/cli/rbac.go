// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"context"
	"errors"
	"strings"
)

type Role string

const (
	RoleView  Role = "view"
	RoleAdmin Role = "admin"
)

type roleCtxKey struct{}

func WithRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, roleCtxKey{}, strings.ToLower(strings.TrimSpace(role)))
}

func roleFromContext(ctx context.Context) Role {
	if ctx == nil {
		return RoleView
	}
	if v := ctx.Value(roleCtxKey{}); v != nil {
		if s, ok := v.(string); ok && s != "" {
			switch strings.ToLower(s) {
			case string(RoleAdmin):
				return RoleAdmin
			default:
				return RoleView
			}
		}
	}
	return RoleView
}

func allowed(required Role, have Role) bool {
	if required == RoleView {
		return true
	}
	if required == RoleAdmin {
		return have == RoleAdmin
	}
	return false
}

var ErrPermissionDenied = errors.New("permission denied")
