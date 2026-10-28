// SPDX-License-Identifier: Apache-2.0
package dnp3

import (
	"crypto/sha256"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

type applicationAssembly struct {
	active, pendingConfirm bool
	seq, fc                byte
	fragments              int
	digest                 [32]byte
	started, touched       time.Time
}

func opposite(dir dpi.StreamDir) dpi.StreamDir {
	if dir == dpi.ClientToServer {
		return dpi.ServerToClient
	}
	if dir == dpi.ServerToClient {
		return dpi.ClientToServer
	}
	return dir
}
func (d *Decoder) peer(k stationKey) *stationContext {
	// Legacy streams have a directional flow hash rather than a common session;
	// never guess their peer identity from station addresses alone.
	k.src, k.dst = k.dst, k.src
	k.master = !k.master
	k.dir = opposite(k.dir)
	return d.stations[k]
}

// Each transport-completed application fragment is independently inspected.
// The conversation retains only bounded sequence/confirmation metadata, never
// concatenates object bytes across application headers or delays policy events.
func (d *Decoder) application(k stationKey, c *stationContext, data []byte, attrs map[string]any, now time.Time) {
	h, fc := data[0], data[1]
	fir, fin, con, uns := h&0x80 != 0, h&0x40 != 0, h&0x20 != 0, h&0x10 != 0
	seq := h & 15
	channel := 0
	if uns {
		channel = 1
	}
	attrs["application_fir"] = fir
	attrs["application_fin"] = fin
	attrs["application_con"] = con
	attrs["application_uns"] = uns
	attrs["application_sequence"] = seq
	if fc == FuncConfirm {
		matched := false
		if peer := d.peer(k); peer != nil {
			a := &peer.application[channel]
			matched = a.pendingConfirm && a.seq == seq
			if matched {
				a.pendingConfirm = false
			}
		}
		attrs["confirmation_matched"] = matched
		// An unmatched confirmation may be capture-midstream or a legacy stream;
		// it carries evidence, not a fabricated protocol violation.
		if !fir || !fin || con {
			mergeCodes(attrs, eventfields.KeyConformance, []string{"dnp3.application_control"})
		}
		return
	}
	if !IsResponse(fc) {
		c.requestSeq = seq
		c.requestFC = fc
		c.requestValid = fir && fin
		if !fir || !fin || uns {
			mergeCodes(attrs, eventfields.KeyConformance, []string{"dnp3.application_control"})
		}
		return
	}
	if fir && !uns {
		if peer := d.peer(k); peer != nil && peer.requestValid {
			attrs["request_matched"] = peer.requestSeq == seq
			if peer.requestSeq == seq {
				attrs["request_function_code"] = peer.requestFC
			}
		}
	}
	if (fc == FuncUnsolicitedResponse) != uns {
		mergeCodes(attrs, eventfields.KeyConformance, []string{"dnp3.application_control"})
	}
	a := &c.application[channel]
	hash := sha256.Sum256(data)
	if a.fragments > 0 && a.seq == seq && a.digest == hash {
		mergeCodes(attrs, eventfields.KeyConformance, []string{"dnp3.application_duplicate"})
		attrs["application_fragment"] = a.fragments
		attrs["application_complete"] = !a.active
		a.touched = now
		return
	}
	if fir {
		if a.active {
			mergeCodes(attrs, eventfields.KeyConformance, []string{"dnp3.application_restart"})
			mergeCodes(attrs, eventfields.KeyUndecoded, []string{"dnp3.application_incomplete"})
		}
		*a = applicationAssembly{active: true, started: now}
	} else if !a.active || seq != (a.seq+1)&15 || fc != a.fc {
		mergeCodes(attrs, eventfields.KeyConformance, []string{"dnp3.application_sequence"})
		mergeCodes(attrs, eventfields.KeyUndecoded, []string{"dnp3.application_incomplete"})
		*a = applicationAssembly{}
		attrs["application_complete"] = false
		return
	}
	if a.fragments >= maxAssemblySegments {
		*a = applicationAssembly{}
		mergeCodes(attrs, eventfields.KeyUndecoded, []string{"dnp3.assembly_limit"})
		attrs["application_complete"] = false
		return
	}
	a.fragments++
	a.seq = seq
	a.fc = fc
	a.digest = hash
	a.pendingConfirm = con
	a.touched = now
	a.active = !fin
	attrs["application_fragment"] = a.fragments
	attrs["application_complete"] = fin
}
