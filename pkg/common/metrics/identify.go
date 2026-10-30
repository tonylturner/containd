// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// These vectors are populated only with fixed protocol/outcome/reason enums.
var (
	IdentificationOutcomes   = promauto.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Subsystem: "identify", Name: "outcomes_total", Help: "Live identification outcomes."}, []string{"protocol", "outcome"})
	IdentificationIncomplete = promauto.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Subsystem: "identify", Name: "incomplete_total", Help: "Live incomplete identification by coverage reason."}, []string{"reason"})
	IdentificationRefusals   = promauto.NewCounter(prometheus.CounterOpts{Namespace: namespace, Subsystem: "identify", Name: "admission_refusals_total", Help: "Live identification incarnations refused by observer capacity, counted once per incarnation."})
	// Transport pressure loses individual packet observations or their loss
	// index, not the entire incarnation's identification admission.
	// Reasons are index_capacity/queue_capacity.
	IdentificationTransportLosses = promauto.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Subsystem: "identify", Name: "transport_losses_total", Help: "Live discovery transport packet admissions lost or unindexed under pressure; counted per packet, not per incarnation."}, []string{"reason"})
	IdentificationEntries         = promauto.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Subsystem: "identify", Name: "entries", Help: "Pending live identification entries."})
	IdentificationBytes           = promauto.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Subsystem: "identify", Name: "charged_bytes", Help: "Charged live identification evidence bytes."})
	IdentificationMarkers         = promauto.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Subsystem: "identify", Name: "markers", Help: "Live incarnation markers."})
	IdentificationBindings        = promauto.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Subsystem: "identify", Name: "bindings", Help: "Live passive decoder bindings."})
)
