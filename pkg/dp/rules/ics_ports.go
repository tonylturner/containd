// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package rules

import "github.com/tonylturner/containd/pkg/dp/ics"

// ICSDecoderPortIn reports the lowest decoder port inside the closed port
// range lo..hi, whatever its transport: the scan selection intercepts TCP
// and refuses to cover any port a decoder claims, so an error can name the
// protocol and port a range covers.
func ICSDecoderPortIn(lo, hi uint16) (ics.DecoderPort, bool) {
	return ics.DecoderPortIn(lo, hi)
}
