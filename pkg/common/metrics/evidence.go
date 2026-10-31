// SPDX-License-Identifier: Apache-2.0
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Audit write counters count persistence attempts, including deduplicated
// AddOnce calls. No identity, destination, action or error text becomes a label.
var (
	AuditWriteFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "audit", Name: "write_failures_total",
		Help: "Failed audit persistence attempts since process start.",
	})
	AuditWriteSuccessesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "audit", Name: "write_successes_total",
		Help: "Successful audit persistence attempts since process start, including deduplicated writes.",
	})
)
