// SPDX-License-Identifier: Apache-2.0
package config

import (
	"errors"
	"fmt"
	"reflect"
	"sort"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
)

// Effective returns a detached runtime projection. Desired state is never
// mutated, including by schema upgrade and validator normalization.
func Effective(cfg *Config, r *mgmtpath.Reservation) (*Config, []ServiceConfigError, error) {
	if cfg == nil {
		return nil, nil, errors.New("config is nil")
	}
	out := cloneDesiredValue(reflect.ValueOf(*cfg)).Interface().(Config)
	coreErr := out.validateCore()
	if p := out.Services.AV.EffectiveFailPolicy(); p != "open" && p != "closed" {
		coreErr = errors.Join(coreErr, errors.New("services.av.failPolicy must be open or closed"))
	}
	if out.Services.AV.BackendDisabled {
		coreErr = errors.Join(coreErr, errors.New("services.av.backendDisabled is runtime-only"))
	}
	coreErr = errors.Join(coreErr, validateManagementCore(&out, r))
	grouped := map[string][]error{}
	serviceErrors, residual := SplitServiceFaults(errors.Join(ValidateServiceConfigs(&out), ValidateManagementServices(out.Services, r)))
	coreErr = errors.Join(coreErr, residual)
	for _, fault := range serviceErrors {
		grouped[fault.Service] = append(grouped[fault.Service], fault.Err)
	}
	faults := make([]ServiceConfigError, 0, len(grouped))
	for name, errs := range grouped {
		faults = append(faults, ServiceConfigError{Service: name, Err: errors.Join(errs...)})
		QuarantineService(&out.Services, name)
	}
	sort.Slice(faults, func(i, j int) bool { return faults[i].Service < faults[j].Service })
	if coreErr != nil {
		return nil, faults, coreErr
	}
	if err := out.Validate(); err != nil {
		return nil, faults, fmt.Errorf("effective config: %w", err)
	}
	if err := ValidateManagementReservation(&out, r); err != nil {
		return nil, faults, err
	}
	return &out, faults, nil
}

// cloneDesiredValue preserves nil collections and concrete predicate values
// (a JSON round trip would turn integer predicates into floating point).
// Config is a finite JSON data model. Unexported migration metadata and immutable
// time internals are copied as values; validation never edits those records.
func cloneDesiredValue(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		if v.Kind() == reflect.Pointer {
			out := reflect.New(v.Type().Elem())
			out.Elem().Set(cloneDesiredValue(v.Elem()))
			return out
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(cloneDesiredValue(v.Elem()))
		return out
	case reflect.Slice:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := range v.Len() {
			out.Index(i).Set(cloneDesiredValue(v.Index(i)))
		}
		return out
	case reflect.Map:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			out.SetMapIndex(iter.Key(), cloneDesiredValue(iter.Value()))
		}
		return out
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				out.Field(i).Set(cloneDesiredValue(v.Field(i)))
			}
		}
		return out
	default:
		return v
	}
}

// CheckWrite permits carried faults only in unchanged service sections.
// A nil baseline requires fault-free new content.
func CheckWrite(baseline, next *Config, r *mgmtpath.Reservation) error {
	_, faults, err := Effective(next, r)
	if err != nil {
		return err
	}
	if len(faults) == 0 {
		return nil
	}
	_, carried, _ := Effective(baseline, r)
	allowed := map[string]bool{}
	for _, f := range carried {
		allowed[f.Service] = true
	}
	var refused []error
	for i := range faults {
		f := &faults[i]
		if baseline == nil || !allowed[f.Service] || !sameService(baseline.Services, next.Services, f.Service) {
			refused = append(refused, f)
		}
	}
	return errors.Join(refused...)
}

// ServiceNames are the independent fault identities, including engine-owned AV
// and WireGuard. IDS policy faults remain core errors.
func ServiceNames() []string {
	return []string{ServiceSyslog, ServiceDNS, ServiceNTP, ServiceAV, ServiceProxy, ServiceDHCP, ServiceWireGuard, ServiceOpenVPN}
}

func sameService(a, b ServicesConfig, name string) bool {
	var x, y ServicesConfig
	copyService(&x, a, name)
	copyService(&y, b, name)
	return reflect.DeepEqual(x, y)
}

func copyService(dst *ServicesConfig, src ServicesConfig, name string) {
	switch name {
	case ServiceSyslog:
		dst.Syslog = src.Syslog
	case ServiceDNS:
		dst.DNS = src.DNS
	case ServiceNTP:
		dst.NTP = src.NTP
	case ServiceAV:
		dst.AV = src.AV
	case ServiceProxy:
		dst.Proxy = src.Proxy
	case ServiceDHCP:
		dst.DHCP = src.DHCP
	case ServiceWireGuard:
		dst.VPN.WireGuard = src.VPN.WireGuard
	case ServiceOpenVPN:
		dst.VPN.OpenVPN = src.VPN.OpenVPN
	}
}

// QuarantineService removes runtime eligibility, not desired state. AV keeps
// the validated gate policy and disables only the scanner backend.
func QuarantineService(s *ServicesConfig, name string) {
	var zero ServicesConfig
	if name == ServiceAV {
		a := s.AV
		s.AV = AVConfig{Enabled: a.Enabled, BackendDisabled: true, FailPolicy: a.FailPolicy,
			HTTPDownload: a.HTTPDownload, HTTPUpload: a.HTTPUpload, Scan: a.Scan}
		return
	}
	copyService(s, zero, name)
}
