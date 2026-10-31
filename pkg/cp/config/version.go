// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	SchemaVersionCurrent = "0.1.9"
)

// Build metadata injected at compile time via -ldflags.
// Release builds should set BuildVersion from the repo VERSION file or release tag.
var (
	BuildVersion = "dev"
	BuildCommit  = "local"
)

type semver struct {
	major int
	minor int
	patch int
}

func parseSemver(v string) (semver, error) {
	// Strip pre-release suffix (e.g. "0.1.1-beta" → "0.1.1").
	if idx := strings.IndexByte(v, '-'); idx >= 0 {
		v = v[:idx]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return semver{}, fmt.Errorf("invalid schema_version %q", v)
	}
	maj, err := strconv.Atoi(parts[0])
	if err != nil {
		return semver{}, fmt.Errorf("invalid schema_version %q", v)
	}
	min, err := strconv.Atoi(parts[1])
	if err != nil {
		return semver{}, fmt.Errorf("invalid schema_version %q", v)
	}
	pat, err := strconv.Atoi(parts[2])
	if err != nil {
		return semver{}, fmt.Errorf("invalid schema_version %q", v)
	}
	return semver{major: maj, minor: min, patch: pat}, nil
}

func compareSemver(a, b semver) int {
	if a.major != b.major {
		if a.major < b.major {
			return -1
		}
		return 1
	}
	if a.minor != b.minor {
		if a.minor < b.minor {
			return -1
		}
		return 1
	}
	if a.patch != b.patch {
		if a.patch < b.patch {
			return -1
		}
		return 1
	}
	return 0
}

// UpgradeInPlace upgrades cfg to SchemaVersionCurrent when possible.
// It rejects configs from newer schemas or from older schemas without a known path.
func UpgradeInPlace(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	cur, _ := parseSemver(SchemaVersionCurrent)
	got := semver{minor: 1}
	if cfg.SchemaVersion != "" {
		var err error
		got, err = parseSemver(cfg.SchemaVersion)
		if err != nil {
			return err
		}
	}
	switch compareSemver(got, cur) {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("config schema_version %s is newer than supported %s", cfg.SchemaVersion, SchemaVersionCurrent)
	default:
		if got.major != cur.major || got.minor != cur.minor {
			return fmt.Errorf("no upgrade path from schema_version %s to %s", cfg.SchemaVersion, SchemaVersionCurrent)
		}
		// The mode audit describes the imported/stored schema, not an
		// intermediate stamp from the ordered industrial-scope upgrade.
		originalSchema := cfg.SchemaVersion
		if beforeIndustrialScope(cfg.SchemaVersion) {
			removed, updated := upgradeIndustrialBuiltins018(cfg)
			if len(removed)+len(updated) > 0 {
				cfg.scopeMigration = newScopeMigration(removed, updated)
			}
			cfg.SchemaVersion = "0.1.8"
		}
		upgradeRuleModes019(cfg, originalSchema)
		cfg.SchemaVersion = SchemaVersionCurrent
		return nil
	}
}
