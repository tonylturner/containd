// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
)

type iecStageOracle struct {
	Version   int `json:"version"`
	Sequences []struct {
		ID     string `json:"id"`
		Peer   string `json:"peer"`
		Frames []struct {
			Direction string `json:"direction"`
			APDU      string `json:"apdu"`
		} `json:"frames"`
	} `json:"sequences"`
}

func TestDS34IEC104(t *testing.T) {
	t.Run("stage-table", func(t *testing.T) {
		now := time.Unix(1, 0)
		for _, row := range iecProcedures {
			t.Run(iecTypeName(row.Type), func(t *testing.T) {
				q := iec104.PairShape{Format: "I", TypeID: row.Type, Cause: row.RequestCause, CA: 1, Objects: []iec104.Object{{IOA: 0, ValueBits: 1}}}
				switch row.Type {
				case 100:
					q.Objects[0].Qualifier = 20
				case 101:
					q.Objects[0].Qualifier = 1
				case 105:
					q.Objects[0].Qualifier = 1
				}
				b := newPairing("iec104", pairResources(), false, nil)
				defer b.close()
				r := q
				r.Cause = row.ConfirmCause
				if row.Type == 102 {
					r.TypeID = 1
					r.Cause = 5
				}
				if _, why := b.inspect(pairIE(r), dpi.ServerToClient, now); why != pairUnpaired {
					t.Fatal(why)
				}
				if why := b.apply(pairIE(q), dpi.ClientToServer, requestPermit{}, now); why != pairOK {
					t.Fatal(why)
				}
				bad := r
				bad.Originator = 1
				if _, why := b.inspect(pairIE(bad), dpi.ServerToClient, now); why != pairUnpaired {
					t.Fatal("originator", why)
				}
				if why := b.apply(pairIE(r), dpi.ServerToClient, requestPermit{}, now); why != pairOK {
					t.Fatal(why)
				}
				if row.Termination {
					if row.Type == 100 || row.Type == 101 {
						data := r
						data.TypeID = 1
						data.Cause = 20
						if row.Type == 101 {
							data.TypeID = 15
							data.Cause = 37
						}
						if why := b.apply(pairIE(data), dpi.ServerToClient, requestPermit{}, now); why != pairOK {
							t.Fatal("data", why)
						}
					}
					r.Cause = 10
					if why := b.apply(pairIE(r), dpi.ServerToClient, requestPermit{}, now); why != pairOK {
						t.Fatal("termination", why)
					}
				}
			})
		}
	})
	t.Run("oracle", func(t *testing.T) {
		observed := map[uint8]bool{}
		checkIECOracle(t, "testdata/iec-stage-oracle.json", false, observed)
		// Until independent peer captures land, the fixture exercises precisely
		// the same strict schema and replay path, without claiming peer proof.
		peer := "../../../test/ds34/peers/iec104/oracle.json"
		if _, err := os.Stat(peer); err == nil {
			checkIECOracle(t, peer, true, observed)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		for _, row := range iecProcedures {
			if row.Clause == "" || !row.StandardOnly && !observed[row.Type] {
				t.Fatalf("type %d has neither standard citation nor peer evidence", row.Type)
			}
		}
	})
}
func iecTypeName(typ uint8) string {
	const digits = "0123456789"
	if typ < 100 {
		return string([]byte{digits[typ/10], digits[typ%10]})
	}
	return string([]byte{'1', digits[(typ/10)%10], digits[typ%10]})
}
func checkIECOracle(t *testing.T, path string, peer bool, observed map[uint8]bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var oracle iecStageOracle
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&oracle); err != nil {
		t.Fatal(path, err)
	}
	if oracle.Version != 1 || len(oracle.Sequences) == 0 {
		t.Fatal("empty or unknown oracle", path)
	}
	for _, seq := range oracle.Sequences {
		if seq.ID == "" || seq.Peer == "" || len(seq.Frames) < 2 {
			t.Fatal("incomplete sequence", seq)
		}
		b := newPairing("iec104", pairResources(), false, nil)
		now := time.Unix(1, 0)
		decoder := iec104.NewDecoder()
		var typ uint8
		for i, frame := range seq.Frames {
			wire, err := hex.DecodeString(frame.APDU)
			if err != nil {
				t.Fatal(err)
			}
			dir := dpi.ClientToServer
			if frame.Direction == "response" {
				dir = dpi.ServerToClient
			} else if frame.Direction != "request" {
				t.Fatal("bad direction", frame.Direction)
			}
			decoded, err := decoder.ParseStream(nil, dpi.StreamView{Session: seq.ID, Dir: dir, Role: dir, Bytes: wire})
			if err != nil || len(decoded.Frames) != 1 || decoded.Consumed != len(wire) {
				t.Fatal(seq.ID, i, err)
			}
			u := decoded.Frames[0].Unit.(*iec104.Unit)
			if i == 0 {
				typ = u.TypeID
			}
			if why := b.apply(decoded.Frames[0], dir, requestPermit{}, now); why != pairOK {
				t.Fatal(path, seq.ID, i, why)
			}
		}
		b.close()
		if peer {
			observed[typ] = true
		}
	}
}
