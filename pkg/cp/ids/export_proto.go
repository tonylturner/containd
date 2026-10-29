// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import "errors"

// ErrUnexportableProto marks a rule whose protocol a Suricata or Snort
// rule cannot express. Rendering it with the generic "ip" keyword would
// fire on unrelated traffic, so the rule is not exported.
var ErrUnexportableProto = errors.New("protocol cannot be exported")
