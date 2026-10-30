// SPDX-License-Identifier: Apache-2.0

package eventfields

// Identification and passive decoding have no enforcement authority. These
// spellings are shared by live telemetry, offline reports and JSON consumers.
const (
	ProtoIdentify               = "identify"
	KindIdentification          = "identification"
	KeyProtocol                 = "protocol"
	KeyIdentificationState      = "identification_state"
	KeyExpected                 = "expected"          // [2]string, endpoint order
	KeyServiceTransport         = "service_transport" // "tcp" or "udp"
	KeyServicePort              = "service_port"
	KeyMismatch                 = "mismatch"
	KeyBinding                  = "binding"                 // "observation", "legacy", "none"
	KeyOutsideRulePortScope     = "outside_rule_port_scope" // bool or "unknown"
	KeyProfileVersion           = "profile_version"
	KeySYNCoverage              = "syn_coverage"              // [2]bool, endpoint order
	KeyObservationOnly          = "observation_only"          // bool true
	KeyBindingSource            = "binding_source"            // "observation"
	KeyIdentificationCandidates = "identification_candidates" // []string
	KeyIdentificationCoverage   = "identification_coverage"
)
