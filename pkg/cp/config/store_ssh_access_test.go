// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSSHPasswordSettingRoundTrip(t *testing.T) {
	for _, setting := range []*bool{nil, new(false), new(true)} {
		cfg := DefaultConfig()
		cfg.System.SSH.AllowPassword = setting
		b, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var loaded Config
		if err := json.Unmarshal(b, &loaded); err != nil {
			t.Fatal(err)
		}
		got := loaded.System.SSH.AllowPassword
		if (got == nil) != (setting == nil) || got != nil && *got != *setting {
			t.Fatalf("setting lost: %s", b)
		}
	}
}

func TestSSHDisableRequiresAccessValidator(t *testing.T) {
	s := candidateStore(t)
	cfg := DefaultConfig()
	cfg.System.SSH.AllowPassword = new(false)
	if err := testSaveCandidate(s, context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "usable admin authorized key") {
		t.Fatalf("stage: %v", err)
	}
}

func TestSSHAccessRecheckedOnPromotion(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "confirmed"}[confirmed], func(t *testing.T) {
			s := candidateStore(t)
			ctx := context.Background()
			keyAvailable := true
			s.SetSSHAccessValidator(func(context.Context, SSHConfig) error {
				if !keyAvailable {
					return errors.New("no usable admin authorized key")
				}
				return nil
			})
			if err := testMutateCandidate(s, ctx, func(c *Config) error {
				c.System.SSH.AllowPassword = new(false)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			cfg, err := s.LoadCandidate(ctx)
			if err != nil || cfg.System.SSH.AllowPassword == nil || *cfg.System.SSH.AllowPassword {
				t.Fatalf("explicit false was not persisted: %v", err)
			}
			keyAvailable = false
			commit := func() error { return testCommit(s, ctx) }
			if confirmed {
				commit = func() error { return testCommitConfirmed(s, ctx, time.Minute) }
			}
			if err := commit(); err == nil {
				t.Fatal("promotion accepted after key disappeared")
			}
			running, err := s.Load(ctx)
			if err != nil || running.System.SSH.AllowPassword != nil {
				t.Fatalf("refused commit modified running: %v", err)
			}
			keyAvailable = true
			if err := commit(); err != nil {
				t.Fatal(err)
			}
			running, err = s.Load(ctx)
			if err != nil || running.System.SSH.AllowPassword == nil || *running.System.SSH.AllowPassword {
				t.Fatalf("disable lost on commit: %v", err)
			}
		})
	}
}

func TestSSHRotationAgeValidation(t *testing.T) {
	for _, days := range []int{-1, MaxSSHHostKeyRotationDays + 1} {
		cfg := DefaultConfig()
		cfg.System.SSH.HostKeyRotationDays = days
		if err := cfg.Validate(); err == nil {
			t.Fatalf("accepted rotation age %d", days)
		}
	}
}
