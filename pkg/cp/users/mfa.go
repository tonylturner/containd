// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package users

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	DefaultTOTPIssuer = "containd"
	TOTPPeriod        = 30
	TOTPSkew          = 1
	MFAGracePeriod    = 7 * 24 * time.Hour
)

type TOTPEnrollment struct {
	Secret    string `json:"secret"`
	URL       string `json:"otpauthURL"`
	QRDataURL string `json:"qrDataURL"`
}

func GenerateTOTPEnrollment(issuer string, accountName string) (*TOTPEnrollment, error) {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		issuer = DefaultTOTPIssuer
	}
	accountName = strings.TrimSpace(accountName)
	if accountName == "" {
		return nil, fmt.Errorf("account name required")
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Period:      TOTPPeriod,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, fmt.Errorf("generate totp: %w", err)
	}
	img, err := key.Image(220, 220)
	if err != nil {
		return nil, fmt.Errorf("generate totp qr: %w", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("encode totp qr: %w", err)
	}
	return &TOTPEnrollment{
		Secret:    key.Secret(),
		URL:       key.URL(),
		QRDataURL: "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()),
	}, nil
}

func NormalizeOTP(code string) string {
	var b strings.Builder
	for _, r := range code {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func ValidateTOTP(secret string, code string, now time.Time) bool {
	secret = strings.TrimSpace(secret)
	code = NormalizeOTP(code)
	if secret == "" || len(code) != 6 {
		return false
	}
	ok, err := totp.ValidateCustom(code, secret, now.UTC(), totp.ValidateOpts{
		Period:    TOTPPeriod,
		Skew:      TOTPSkew,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && ok
}

func MFAGraceDeadline(now time.Time) time.Time {
	return now.UTC().Add(MFAGracePeriod)
}

func HasPendingMFARequirement(u *StoredUser) bool {
	if u == nil {
		return false
	}
	return u.MFARequired && !u.MFAEnabled
}

func IsMFAGraceExpired(u *StoredUser, now time.Time) bool {
	if !HasPendingMFARequirement(u) {
		return false
	}
	if u.MFAGraceUntil == nil {
		return true
	}
	return !now.UTC().Before(u.MFAGraceUntil.UTC())
}
