// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/identify"
)

// IdentificationEvent constructs the one non-ICS identification event. Scope
// is bool or "unknown". Directional expectations and SYN coverage use Meta order.
func IdentificationEvent(d identify.Decision, meta identify.Meta, syn [2]bool, binding Binding, scope any, at time.Time) dpi.Event {
	var candidates []string
	reason := string(d.Coverage)
	var reasons []string
	for _, r := range d.Results {
		if r.State == identify.Candidate || r.State == identify.Confirmed {
			candidates = append(candidates, string(r.Protocol))
		}
		if r.Protocol != "" && r.Reason != "" {
			reasons = append(reasons, string(r.Protocol)+": "+r.Reason)
		}
		if r.Protocol != "" && r.Protocol == d.Protocol {
			reason = r.Reason
		}
	}
	if d.Protocol == "" && len(reasons) > 0 {
		reason = strings.Join(reasons, "; ")
	}
	transport := "tcp"
	if meta.Transport == 17 {
		transport = "udp"
	}
	// Prefer the endpoint whose registry expectation matches content, otherwise
	// the SYN server endpoint (or endpoint 1 when roles are not known).
	service := 1
	for i, p := range d.Expected {
		if p != "" && p == d.Protocol {
			service = i
		}
	}
	mismatch := false
	for _, expected := range d.Expected {
		mismatch = mismatch || expected != "" && d.Protocol != "" && expected != d.Protocol
	}
	if _, ok := scope.(bool); !ok {
		scope = "unknown"
	}
	return dpi.Event{Proto: eventfields.ProtoIdentify, Kind: eventfields.KindIdentification, Timestamp: at,
		Attributes: map[string]any{
			eventfields.KeyProtocol: string(d.Protocol), eventfields.KeyIdentificationState: string(d.State),
			eventfields.KeyReason: reason, eventfields.KeyIdentificationCoverage: string(d.Coverage),
			eventfields.KeyExpected:         [2]string{string(d.Expected[0]), string(d.Expected[1])},
			eventfields.KeyServiceTransport: transport, eventfields.KeyServicePort: meta.Ports[service],
			eventfields.KeyMismatch: mismatch, eventfields.KeyBinding: string(binding),
			eventfields.KeyOutsideRulePortScope: scope, eventfields.KeyProfileVersion: identify.ProfileVersion,
			eventfields.KeySYNCoverage: syn, eventfields.KeyIdentificationCandidates: candidates,
		}}
}
