// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapi

import (
	"context"
	"fmt"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/learn"
)

// ListLearnProfiles fetches the ICS traffic profiles the engine has learned.
func (c *HTTPClient) ListLearnProfiles(ctx context.Context) ([]learn.LearnedProfile, error) {
	var out []learn.LearnedProfile
	if err := c.getJSON(ctx, "/internal/learn/profiles", "engine learn profiles status", &out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, fmt.Errorf("invalid engine learn profile list")
	}
	return out, nil
}

// GenerateLearnRules fetches the allowlist rules the engine generates from its
// learned profiles. It does not stage or apply them.
func (c *HTTPClient) GenerateLearnRules(ctx context.Context) ([]config.Rule, error) {
	var out []config.Rule
	if err := c.getJSON(ctx, "/internal/learn/rules", "engine learn rules status", &out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, fmt.Errorf("invalid engine learn rule list")
	}
	return out, nil
}

// ClearLearnData discards every profile the engine has learned.
func (c *HTTPClient) ClearLearnData(ctx context.Context) error {
	return c.deleteOK(ctx, "/internal/learn", "engine learn clear status")
}
