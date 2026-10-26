// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"testing"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
)

func TestCompilerSettings(t *testing.T) {
	r := &mgmtpath.Reservation{}
	for _, table := range []string{"", "custom_table"} {
		c := NewCompilerWithSettings(CompilerSettings{TableName: table, NFLogGroup: 65535, NFQueueGroup: 207}, r)
		want := table
		if want == "" {
			want = "containd"
		}
		if c.TableName != want || c.NFLogGroup != 65535 || c.QueueID != 207 || c.ManagementReservation != r || c.IEC104EnvelopeOpen {
			t.Fatalf("compiler = %+v", c)
		}
	}
}
