// SPDX-License-Identifier: Apache-2.0

package mgmttls

import (
	"crypto/x509"
	"testing"
)

func TestFingerprint(t *testing.T) {
	const want = "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD"
	leaf := &x509.Certificate{Raw: []byte("abc")}
	if got := Fingerprint(leaf); got != want {
		t.Fatalf("Fingerprint = %s; want %s", got, want)
	}
	if got := Fingerprint(nil); got != "" {
		t.Fatalf("nil fingerprint = %q", got)
	}
}
