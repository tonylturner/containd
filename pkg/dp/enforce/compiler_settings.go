// SPDX-License-Identifier: Apache-2.0

package enforce

import "github.com/tonylturner/containd/pkg/common/mgmtpath"

// CompilerSettings are the enforcement inputs shared by apply and preview.
// Runtime envelope state is deliberately not a configuration setting.
type CompilerSettings struct {
	TableName    string
	NFLogGroup   uint16
	NFQueueGroup uint16
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
	return c
}
