// SPDX-License-Identifier: Apache-2.0

package enforce

import "github.com/tonylturner/containd/pkg/common/mgmtpath"

// Default loopback listener ports of the scanning gate: plain connections
// and connections whose upstream leg is masqueraded.
const (
	DefaultGatePlainPort uint16 = 18100
	DefaultGateMasqPort  uint16 = 18101
)

// CompilerSettings are the enforcement inputs shared by apply and preview.
// Runtime envelope state is deliberately not a configuration setting.
type CompilerSettings struct {
	TableName    string
	NFLogGroup   uint16
	NFQueueGroup uint16
	// GatePlainPort and GateMasqPort are the scanning gate's loopback
	// listener ports for plain and masqueraded connections. Zero disables
	// gate delivery; the caller applies DefaultGatePlainPort and
	// DefaultGateMasqPort when the gate is wanted.
	GatePlainPort uint16
	GateMasqPort  uint16
}

// NewCompilerWithSettings builds a fresh compiler; reservation is process-owned
// authority, never supplied by a candidate snapshot.
func NewCompilerWithSettings(s CompilerSettings, reservation *mgmtpath.Reservation) *Compiler {
	c := NewCompiler()
	if s.TableName != "" {
		c.TableName = s.TableName
	}
	c.ManagementReservation = reservation
	c.NFLogGroup = int(s.NFLogGroup)
	c.QueueID = int(s.NFQueueGroup)
	c.GatePlainPort, c.GateMasqPort = s.GatePlainPort, s.GateMasqPort
	return c
}
