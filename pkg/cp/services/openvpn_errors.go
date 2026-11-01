// SPDX-License-Identifier: Apache-2.0
package services

import "errors"

// Credential capability errors let callers distinguish rejected requests from
// authority storage and runtime failures without inspecting error strings.
var (
	ErrOpenVPNUnknownCredential = errors.New("unknown OpenVPN credential")
	ErrOpenVPNInvalidClientName = errors.New("client name must be an exact lowercase filename-safe name (1-64 characters)")
	ErrOpenVPNClientNameIssued  = errors.New("client name already issued")
	ErrOpenVPNServerNotActive   = errors.New("managed OpenVPN server is not active")
	ErrOpenVPNCredentialRevoked = errors.New("OpenVPN credential is revoked")
)
