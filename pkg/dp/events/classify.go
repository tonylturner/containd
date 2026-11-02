// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package events

import "github.com/tonylturner/containd/pkg/common/telemetry"

// Classify returns every telemetry class matched by an event.
func Classify(e Event) []telemetry.EventClass {
	var classes []telemetry.EventClass
	if e.Proto == "ids" && e.Kind == "alert" {
		classes = append(classes, telemetry.ClassIDSAlert)
	}
	if e.Kind == "service.av.detected" {
		classes = append(classes, telemetry.ClassAVDetection)
	}
	if e.Kind == "service.av.block_flow" {
		classes = append(classes, telemetry.ClassAVBlock)
	}
	if e.Proto == "modbus" && e.Kind == "request" && modbusWriteEvent(e) {
		classes = append(classes, telemetry.ClassModbusWrite)
	}
	return classes
}

func modbusWriteEvent(e Event) bool {
	if e.Attributes == nil {
		return false
	}
	isWrite, ok := e.Attributes["is_write"].(bool)
	return ok && isWrite
}
