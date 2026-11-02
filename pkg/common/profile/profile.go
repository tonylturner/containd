// SPDX-License-Identifier: Apache-2.0

// Package profile resolves the immutable deployment profile of this process.
package profile

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

type Profile string

const (
	Training Profile = "training"
	Strict   Profile = "strict"
	EnvVar           = "CONTAIND_PROFILE"
)

var loaded struct {
	once      sync.Once
	value     Profile
	err       error
	defaulted bool
}

func Parse(value string) (Profile, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(Training):
		return Training, nil
	case string(Strict):
		return Strict, nil
	default:
		return "", fmt.Errorf("%s=%q: use training or strict", EnvVar, value)
	}
}

// Load reads the environment exactly once, caching failures as well as success.
func Load() (Profile, error) {
	loaded.once.Do(func() {
		value := os.Getenv(EnvVar)
		loaded.value, loaded.err = Parse(value)
		loaded.defaulted = strings.TrimSpace(value) == ""
	})
	return loaded.value, loaded.err
}

// Current returns the loaded profile. Before Load, it returns Training without
// reading the environment. Executable entry points must call Load first.
func Current() Profile {
	if loaded.value == "" {
		return Training
	}
	return loaded.value
}

func IsStrict() bool { return Current() == Strict }

// Defaulted reports whether Load selected training from an empty environment.
func Defaulted() bool { return loaded.defaulted }

func Refusal(what, why string) error {
	if why == "" {
		return fmt.Errorf("%s=strict refuses %s", EnvVar, what)
	}
	return fmt.Errorf("%s=strict refuses %s: %s", EnvVar, what, why)
}
