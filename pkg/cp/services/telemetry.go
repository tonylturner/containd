// SPDX-License-Identifier: Apache-2.0

package services

import (
	"context"
	"sort"
	"time"

	wire "github.com/tonylturner/containd/pkg/common/telemetry"
)

// CounterReader binds the lifetime management counters to one process epoch.
// Sampling never probes service daemons or reads their status APIs.
func (m *Manager) CounterReader(bootID string) wire.CounterReader {
	return &serviceCounterReader{manager: m, bootID: bootID}
}

type serviceCounterReader struct {
	manager *Manager
	bootID  string
	invalid []wire.CounterSample
}

func (r *serviceCounterReader) TelemetryCounters(context.Context) (wire.CounterSnapshot, error) {
	m := r.manager
	r.invalid = nil
	out := wire.CounterSnapshot{BootID: r.bootID, SampledAt: time.Now().UTC()}
	m.sparkMu.Lock()
	names := map[string]bool{}
	for _, name := range []string{"syslog", "dns", "ntp", "proxy", "dhcp", "vpn", "av", "wireguard", "openvpn"} {
		names[name] = true
	}
	for name := range m.primary {
		names[name] = true
	}
	for name := range m.errs {
		names[name] = true
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	for _, name := range ordered {
		for _, counter := range []struct {
			metric wire.Metric
			meter  *meter
		}{{wire.ServiceEvents, m.primary[name]}, {wire.ServiceErrors, m.errs[name]}} {
			mt := counter.meter
			dims := map[string]string{"service": name}
			// Signed corrections are exposed as unavailable for one scrape even if
			// later increments already recovered above the previous total.
			if mt != nil && (mt.signed || mt.total < 0) {
				out.Unavailable = append(out.Unavailable, wire.SourceUnavailable{Source: "service", Metric: counter.metric, Dims: dims, Reason: "signed counter correction"})
				r.invalid = append(r.invalid, wire.CounterSample{Metric: counter.metric, Dims: dims, Origin: wire.OriginReal})
				mt.signed = false
				continue
			}
			out.Samples = append(out.Samples, wire.CounterSample{Metric: counter.metric, Dims: dims, Value: uint64(mt.count()), Epoch: r.bootID, Origin: wire.OriginReal})
		}
	}
	m.sparkMu.Unlock()
	for _, counts := range m.telemetry.TelemetryCounts() {
		out.Samples = append(out.Samples, wire.CounterSample{Metric: wire.EventsTotal, Dims: map[string]string{"source": "services"}, Value: counts.Total, Epoch: r.bootID, Origin: counts.Origin})
		for _, class := range []wire.EventClass{wire.ClassIDSAlert, wire.ClassAVDetection, wire.ClassAVBlock, wire.ClassModbusWrite} {
			out.Samples = append(out.Samples, wire.CounterSample{Metric: wire.EventsClass, Dims: map[string]string{"source": "services", "class": string(class)}, Value: counts.Classes[class], Epoch: r.bootID, Origin: counts.Origin})
		}
	}
	return out, nil
}

// TelemetryBaselines lists local series whose signed corrections invalidate the
// previous sample. Only the single management sampler owns this reader.
func (r *serviceCounterReader) TelemetryBaselines() []wire.CounterSample { return r.invalid }
