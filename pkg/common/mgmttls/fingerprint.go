// SPDX-License-Identifier: Apache-2.0

package mgmttls

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
)

// Fingerprint returns the SHA-256 of the DER leaf, in uppercase colon-separated
// hex. A missing leaf has no fingerprint.
func Fingerprint(leaf *x509.Certificate) string {
	if leaf == nil {
		return ""
	}
	sum := sha256.Sum256(leaf.Raw)
	encoded := strings.ToUpper(hex.EncodeToString(sum[:]))
	var out strings.Builder
	for i := 0; i < len(encoded); i += 2 {
		if i != 0 {
			out.WriteByte(':')
		}
		out.WriteString(encoded[i : i+2])
	}
	return out.String()
}
