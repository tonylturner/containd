// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"reflect"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

// Retain an owned bounded decoded-event copy, never raw payloads or a JSON
// round trip on the forwarding path. Normalization belongs to the worker.
func ownEvidenceEvents(events []dpi.Event) ([]dpi.Event, int, bool) {
	if len(events) > 4096 {
		return nil, 0, false
	}
	budget := copyBudget{bytes: 1 << 20, nodes: 65536}
	owned := make([]dpi.Event, len(events))
	for i, ev := range events {
		owned[i] = ev
		if len(ev.Attributes) > budget.nodes {
			return nil, 0, false
		}
		if !budget.take(len(ev.FlowID) + len(ev.Proto) + len(ev.Kind) + len(ev.CorrelationStatus) + 128) {
			return nil, 0, false
		}
		attrs := make(map[string]any, len(ev.Attributes))
		for k, v := range ev.Attributes {
			if k == "raw_hex" || k == "payload" || k == "raw" {
				continue
			}
			if !budget.take(len(k)) {
				return nil, 0, false
			}
			copy, ok := budget.clone(reflect.ValueOf(v), 0)
			if !ok {
				return nil, 0, false
			}
			if copy.IsValid() {
				attrs[k] = copy.Interface()
			} else {
				attrs[k] = nil
			}
		}
		owned[i].Attributes = attrs
	}
	return owned, (1 << 20) - budget.bytes, true
}

type copyBudget struct{ bytes, nodes int }

func (b *copyBudget) take(n int) bool { b.bytes -= n; b.nodes--; return b.bytes >= 0 && b.nodes >= 0 }
func (b *copyBudget) clone(v reflect.Value, depth int) (reflect.Value, bool) {
	if depth > 16 || !b.take(8) {
		return reflect.Value{}, false
	}
	if !v.IsValid() {
		return v, true
	}
	if v.Type() == reflect.TypeFor[time.Time]() {
		return v, true
	}
	switch v.Kind() {
	case reflect.String:
		return v, b.take(len(v.String()))
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		return v, true
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			return reflect.Zero(v.Type()), true
		}
		inner, ok := b.clone(v.Elem(), depth+1)
		if !ok {
			return reflect.Value{}, false
		}
		out := reflect.New(v.Type()).Elem()
		if v.Kind() == reflect.Pointer {
			out.Set(reflect.New(v.Type().Elem()))
			out.Elem().Set(inner)
		} else {
			out.Set(inner)
		}
		return out, true
	case reflect.Map:
		if v.IsNil() {
			return reflect.Zero(v.Type()), true
		}
		if v.Type().Key().Kind() != reflect.String || v.Len() > b.nodes {
			return reflect.Value{}, false
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		it := v.MapRange()
		for it.Next() {
			if !b.take(len(it.Key().String())) {
				return reflect.Value{}, false
			}
			copy, ok := b.clone(it.Value(), depth+1)
			if !ok {
				return reflect.Value{}, false
			}
			out.SetMapIndex(it.Key(), copy)
		}
		return out, true
	case reflect.Slice, reflect.Array:
		if v.Len() > b.nodes {
			return reflect.Value{}, false
		}
		out := reflect.New(v.Type()).Elem()
		if v.Kind() == reflect.Slice {
			if v.IsNil() {
				return out, true
			}
			out.Set(reflect.MakeSlice(v.Type(), v.Len(), v.Len()))
		}
		for i := range v.Len() {
			copy, ok := b.clone(v.Index(i), depth+1)
			if !ok {
				return reflect.Value{}, false
			}
			out.Index(i).Set(copy)
		}
		return out, true
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		for i := range v.NumField() {
			if !out.Field(i).CanSet() || !v.Field(i).CanInterface() {
				return reflect.Value{}, false
			}
			copy, ok := b.clone(v.Field(i), depth+1)
			if !ok {
				return reflect.Value{}, false
			}
			out.Field(i).Set(copy)
		}
		return out, true
	default:
		return reflect.Value{}, false
	}
}
