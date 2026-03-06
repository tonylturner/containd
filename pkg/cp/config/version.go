package config

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	SchemaVersionCurrent = "0.1.0"
)

// Build metadata injected at compile time via -ldflags.
var (
	BuildVersion = "dev"
	BuildCommit  = "unknown"
)

type semver struct {
	major int
	minor int
	patch int
}

func parseSemver(v string) (semver, error) {
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
	if cfg.SchemaVersion == "" {
		cfg.SchemaVersion = SchemaVersionCurrent
		return nil
	}
	cur, _ := parseSemver(SchemaVersionCurrent)
	got, err := parseSemver(cfg.SchemaVersion)
	if err != nil {
		return err
	}
	switch compareSemver(got, cur) {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("config schema_version %s is newer than supported %s", cfg.SchemaVersion, SchemaVersionCurrent)
	default:
		// For now, accept older patch versions of the same major/minor and bump.
		if got.major == cur.major && got.minor == cur.minor {
			cfg.SchemaVersion = SchemaVersionCurrent
			return nil
		}
		return fmt.Errorf("no upgrade path from schema_version %s to %s", cfg.SchemaVersion, SchemaVersionCurrent)
	}
}
