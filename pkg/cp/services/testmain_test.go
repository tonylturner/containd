// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	_ = os.Setenv("CONTAIND_LOG_FILE", "off")
	os.Exit(m.Run())
}
