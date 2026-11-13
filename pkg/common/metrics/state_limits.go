// SPDX-License-Identifier: Apache-2.0
package metrics

import (
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

var stateLimitsReader atomic.Pointer[func() limits.Snapshot]

// SetStateLimitsReader follows the live engine across rebuilds without
// registering duplicate collectors in combined mode. Nil disables sampling.
func SetStateLimitsReader(read func() limits.Snapshot) {
	stateLimitsReader.Store(&read)
}

var stateTables = []limits.Table{
	limits.TableFlows, limits.TableInspection, limits.TableTopTalkers,
	limits.TableRateTrackers, limits.TableIECSessions, limits.TableIECReconnect,
	limits.TableInventoryPoints, limits.TableSignatureWindows, limits.TableConformance,
	limits.TableVerdictCache, limits.TablePickupReset, limits.TableHTTPCorrelation,
}

var stateGaugeDescs = []*prometheus.Desc{
	prometheus.NewDesc("containd_dp_state_entries", "Current retained entries or reserved directional flow slots.", []string{"table"}, nil),
	prometheus.NewDesc("containd_dp_state_limit", "Current table capacity; inspection_bytes is in bytes, zero means no aggregate count cap.", []string{"table"}, nil),
	prometheus.NewDesc("containd_dp_state_charged_bytes", "Retained inspection allocation charges, not total engine memory.", []string{"table"}, nil),
	prometheus.NewDesc("containd_dp_state_high_water", "Generation high water in table units.", []string{"table"}, nil),
}
var stateHitsDesc = prometheus.NewDesc("containd_dp_state_limit_hits_total", "Process-lifetime state limit hits.", []string{"table", "reason", "mode"}, nil)
var inspectionBytesDesc = prometheus.NewDesc("containd_dp_inspection_bytes", "Retained inspection allocation charges by category.", []string{"category"}, nil)

type stateLimitsCollector struct{}

func (stateLimitsCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range stateGaugeDescs {
		ch <- desc
	}
	ch <- stateHitsDesc
	ch <- inspectionBytesDesc
}

func (stateLimitsCollector) Collect(ch chan<- prometheus.Metric) {
	read := stateLimitsReader.Load()
	if read == nil || *read == nil {
		return // Unavailable is not an empty, healthy engine.
	}
	snapshot := (*read)()
	for _, table := range stateTables {
		for _, status := range snapshot.Tables {
			if status.Table != table {
				continue
			}
			values := []int64{status.Entries, status.Limit, status.ChargedBytes, status.HighWater}
			for i, value := range values {
				ch <- prometheus.MustNewConstMetric(stateGaugeDescs[i], prometheus.GaugeValue, float64(value), string(table))
			}
			// Iterate only the closed enums, never labels from arbitrary snapshot text.
			for _, reason := range []limits.Reason{limits.ReasonRefused, limits.ReasonEvicted, limits.ReasonTruncated} {
				for _, mode := range []limits.Mode{limits.ModeEnforce, limits.ModeMonitor, limits.ModeObserve} {
					var total uint64
					for _, hit := range status.Hits {
						if hit.Reason == reason && hit.Mode == mode {
							total += hit.Total
						}
					}
					ch <- prometheus.MustNewConstMetric(stateHitsDesc, prometheus.CounterValue, float64(total), string(table), string(reason), string(mode))
				}
			}
			break
		}
	}
	for _, category := range []limits.Category{limits.CategoryStream, limits.CategoryDecoder, limits.CategoryHeld, limits.CategoryPairing} {
		name := category.String()
		ch <- prometheus.MustNewConstMetric(inspectionBytesDesc, prometheus.GaugeValue, float64(snapshot.Budget.ByCategory[name]), name)
	}
}

func init() { prometheus.MustRegister(stateLimitsCollector{}) }
