// SPDX-License-Identifier: Apache-2.0

// Package limits defines retained traffic state accounting and its public snapshot.
// It does not decide packet policy or publish events.
package limits

import (
	"errors"
	"fmt"
)

const (
	DefaultMaxFlows                 = 16384
	MinMaxFlows                     = 1024
	MaxMaxFlows                     = 262144
	DefaultMaxTopTalkers            = 8192
	MinMaxTopTalkers                = 64
	MaxMaxTopTalkers                = 262144
	DefaultMaxInspectionBytes int64 = 64 << 20
	MinMaxInspectionBytes     int64 = 8 << 20
	MaxMaxInspectionBytes     int64 = 1 << 30
	MaxRateTrackers                 = 8192
	MaxIECReconnect                 = 4096
	MaxInventoryPoints              = 65536
	MaxSignatureWindows             = 4096
	MaxSignatureValues              = 256
	MaxSignatureValueBytes          = 16 << 10
	MaxConformanceConnections       = 65536
	MaxConformanceCodes             = 64
	MaxVerdictCache                 = 65536
	MaxPickupReset                  = 4096
	MaxHTTPCorrelation              = 64
	MaxIECSessions                  = 4096
	MaxProtocols                    = 64
)

type Limits struct {
	MaxFlows, MaxTopTalkers int
	MaxInspectionBytes      int64
}

func Default() Limits {
	return Limits{DefaultMaxFlows, DefaultMaxTopTalkers, DefaultMaxInspectionBytes}
}

// Validate checks effective operator values. Zero must be resolved before calling.
func (l Limits) Validate() error {
	var errs []error
	for _, f := range []struct {
		name            string
		value, min, max int64
	}{
		{"maxFlows", int64(l.MaxFlows), MinMaxFlows, MaxMaxFlows},
		{"maxTopTalkers", int64(l.MaxTopTalkers), MinMaxTopTalkers, MaxMaxTopTalkers},
		{"maxInspectionBytes", l.MaxInspectionBytes, MinMaxInspectionBytes, MaxMaxInspectionBytes},
	} {
		if f.value < f.min || f.value > f.max {
			errs = append(errs, fmt.Errorf("dataplane.limits.%s must be between %d and %d", f.name, f.min, f.max))
		}
	}
	return errors.Join(errs...)
}
