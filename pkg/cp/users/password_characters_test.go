// SPDX-License-Identifier: Apache-2.0
package users

import "testing"

func TestPasswordMinimumCountsRunes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password string
		valid    bool
	}{
		{"five runes eight bytes", "Aa1😀x", false},
		{"seven runes", "Aa1界界界界", false},
		{"eight runes", "Aa1界界界界界", true},
		{"ASCII eight", "Abcdefg1", true},
		{"non-ASCII uppercase only", "Äbcdefg1", false},
		{"non-ASCII lowercase only", "Aä界界界界界1", false},
		{"non-ASCII digit only", "Abcdefg１", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePassword(tc.password)
			if (err == nil) != tc.valid {
				t.Fatalf("validatePassword = %v, want valid=%v", err, tc.valid)
			}
			if !tc.valid && !IsPasswordPolicyError(err) {
				t.Fatalf("want password policy error, got %v", err)
			}
		})
	}
}
