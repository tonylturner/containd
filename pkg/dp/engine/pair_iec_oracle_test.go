// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
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
	t.Run("mismatch-and-stages", testDS34IECMismatchStages)
	t.Run("inline-solicited", func(t *testing.T) { testDS34SolicitedRuntime(t, runtimePairCases()[2]) })
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
		fixture := readIECOracle(t, "testdata/iec-stage-oracle.json")
		for _, seq := range fixture.Sequences {
			if why := replayIECSequence(t, seq, observed); why != pairOK {
				t.Fatal(seq.ID, why)
			}
		}
		clear(observed)
		oracle := readIECOracle(t, "../../../test/ds34/peers/iec104/oracle.json")
		var expectations iecOracleExpectations
		strictIECJSON(t, "testdata/iec-stage-expectations.json", &expectations)
		if expectations.Version != 1 {
			t.Fatal("unknown expectation version")
		}
		outcomes, pending := expectations.index(t)
		for _, group := range expectations.Pending {
			if len(group.IDs) == 0 {
				t.Run("pending-"+group.Decision, func(t *testing.T) {
					t.Errorf("PENDING %s: no peer sequence witnesses this procedure", group.Decision)
				})
			}
		}
		seen := map[string]bool{}
		for _, seq := range oracle.Sequences {
			if seen[seq.ID] {
				t.Fatal("duplicate oracle id", seq.ID)
			}
			seen[seq.ID] = true
			t.Run(seq.ID, func(t *testing.T) {
				why := replayIECSequence(t, seq, observed)
				if decision, ok := pending[seq.ID]; ok {
					t.Errorf("PENDING %s: %s (current table outcome %s)", seq.ID, decision, why)
					return
				}
				want, ok := outcomes[seq.ID]
				if !ok {
					t.Fatal("missing oracle expectation", seq.ID)
				}
				if why != want {
					t.Fatalf("outcome %s, want %s", why, want)
				}
			})
		}
		for id := range outcomes {
			if !seen[id] {
				t.Errorf("expectation has no oracle sequence: %s", id)
			}
		}
		for id := range pending {
			if !seen[id] {
				t.Errorf("pending id has no oracle sequence: %s", id)
			}
		}
		for _, row := range iecProcedures {
			if row.Clause == "" || !row.StandardOnly && !observed[row.Type] {
				t.Errorf("type %d lacks required stage evidence", row.Type)
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

type iecOracleExpectation struct {
	ID      string     `json:"id"`
	Outcome string     `json:"outcome"`
	Reason  pairReason `json:"reason,omitempty"`
}
type iecOracleExpectations struct {
	Version  int                    `json:"version"`
	Outcomes []iecOracleExpectation `json:"outcomes"`
	Pending  []struct {
		Decision string   `json:"decision"`
		IDs      []string `json:"ids"`
	} `json:"pending"`
}

func (e iecOracleExpectations) index(t *testing.T) (map[string]pairReason, map[string]string) {
	t.Helper()
	outcomes, pending := map[string]pairReason{}, map[string]string{}
	for _, x := range e.Outcomes {
		if x.ID == "" || outcomes[x.ID] != "" {
			t.Fatal("empty or duplicate expected id", x.ID)
		}
		switch x.Outcome {
		case "accept":
			if x.Reason != "" {
				t.Fatal("accepted sequence has reset reason", x.ID)
			}
			outcomes[x.ID] = pairOK
		case "reset":
			switch x.Reason {
			case pairUnpaired, pairExpired, pairAmbiguous, pairUnsupported, pairMismatch:
				outcomes[x.ID] = x.Reason
			default:
				t.Fatal("invalid reset reason", x.ID, x.Reason)
			}
		default:
			t.Fatal("invalid expected outcome", x.ID, x.Outcome)
		}
	}
	for _, group := range e.Pending {
		if group.Decision == "" {
			t.Fatal("missing pending decision")
		}
		for _, id := range group.IDs {
			if id == "" || pending[id] != "" || outcomes[id] != "" {
				t.Fatal("empty or duplicate pending id", id)
			}
			pending[id] = group.Decision
		}
	}
	return outcomes, pending
}
func strictIECJSON(t *testing.T, path string, out any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		t.Fatal(path, err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		t.Fatal(path, "trailing JSON", err)
	}
}
func readIECOracle(t *testing.T, path string) iecStageOracle {
	t.Helper()
	var oracle iecStageOracle
	strictIECJSON(t, path, &oracle)
	if oracle.Version != 1 || len(oracle.Sequences) == 0 {
		t.Fatal("empty or unknown oracle", path)
	}
	return oracle
}
func replayIECSequence(t *testing.T, seq struct {
	ID     string `json:"id"`
	Peer   string `json:"peer"`
	Frames []struct {
		Direction string `json:"direction"`
		APDU      string `json:"apdu"`
	} `json:"frames"`
}, observed map[uint8]bool) pairReason {
	t.Helper()
	if seq.ID == "" || seq.Peer == "" || len(seq.Frames) < 2 {
		t.Fatal("incomplete sequence", seq.ID)
	}
	b := newPairing("iec104", pairResources(), false, nil)
	defer b.close()
	decoder := iec104.NewDecoder()
	now := time.Unix(1, 0)
	outcome := pairOK
	for i, frame := range seq.Frames {
		wire, err := hex.DecodeString(frame.APDU)
		if err != nil {
			t.Fatal(seq.ID, i, err)
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
		u, ok := decoded.Frames[0].Unit.(*iec104.Unit)
		if !ok {
			t.Fatal("missing typed IEC unit", seq.ID, i)
		}
		if u.Format == "I" {
			observed[u.TypeID] = true
		}
		if outcome == pairOK {
			outcome = b.apply(decoded.Frames[0], dir, requestPermit{}, now)
		}
	}
	return outcome
}
