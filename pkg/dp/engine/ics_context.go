// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/project"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// evalContextsFromDPIEvent is shared by retained-event preview and live
// evaluation. Every object gets the full rule precedence independently.
func evalContextsFromDPIEvent(snap *rules.Snapshot, state *flow.State, pkt *dpi.ParsedPacket, ev dpi.Event, srcZone, dstZone string) []rules.EvalContext {
	if state == nil || pkt == nil || !isRuleEvaluableICSEvent(ev.Proto) || isStreamErrorEvent(ev) {
		return nil
	}
	key := state.ServiceKey()
	base := rules.EvalContext{
		SrcZone: srcZone, DstZone: dstZone, SrcIP: key.OpenerIP(), DstIP: key.ServerIP(),
		Proto: strings.ToLower(pkt.Proto), Port: strconv.Itoa(int(servicePort(state, pkt))),
		Identities: snap.IdentitiesOf(key.OpenerIP()),
	}
	objects := icsContextsFromDPIEvent(state, ev, nil)
	contexts := make([]rules.EvalContext, len(objects))
	for i := range objects {
		contexts[i] = base
		contexts[i].ICS = &objects[i]
	}
	return contexts
}

// icsContextsFromDPIEvent delegates to the shared pure projector.
func icsContextsFromDPIEvent(state *flow.State, ev dpi.Event, safeRead func(map[string]any) bool) []rules.ICSContext {
	return project.Objects(state, ev, safeRead)
}
