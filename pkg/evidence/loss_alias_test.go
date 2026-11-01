// SPDX-License-Identifier: Apache-2.0
package evidence

import (
	"encoding/json"
	"testing"
)

func TestLossAcrossVerifiedNATAliases(t *testing.T) {
	original := Tuple{Source: Endpoint{IP: "10.10.0.5", Port: 41000}, Destination: Endpoint{IP: "10.20.0.4", Port: 502}, Transport: "tcp"}
	reply := Tuple{Source: Endpoint{IP: "10.20.0.4", Port: 502}, Destination: Endpoint{IP: "10.20.0.2", Port: 52000}, Transport: "tcp"}
	for _, ports := range []bool{false, true} {
		ds := Dataset{}
		ds.RecordLoss(CollectionLoss{Code: "capture_loss", ConnectionID: "admission-incarnation", Scope: LossScope{Source: reply.Source, Destination: reply.Destination, Transport: "tcp", Ports: ports}})
		for _, id := range []string{"admission-incarnation", "earlier-incarnation", "later-incarnation"} {
			o := Observation{Source: SourceLive, ConnectionID: id, Authority: Authority{Wire: original, Correlation: "verified", Aliases: &WireAliases{Original: original, Reply: reply}}}
			data, err := json.Marshal(o)
			if err != nil {
				t.Fatal(err)
			}
			o = Observation{}
			if err := json.Unmarshal(data, &o); err != nil {
				t.Fatal(err)
			}
			if !ds.LossTouches(o) {
				t.Fatalf("alias escaped: ports=%v id=%s", ports, id)
			}
			// Same original hosts but different source ports and NAT translations.
			o.Authority.Wire.Source.Port++
			o.Authority.Aliases.Original = o.Authority.Wire
			o.Authority.Aliases.Reply.Destination.Port++
			if got := ds.LossTouches(o); got != (!ports || id == "admission-incarnation") {
				t.Fatalf("disjointness: ports=%v id=%s got=%v", ports, id, got)
			}
		}
	}
}

func TestLossWithUnprovedAliasDisjointness(t *testing.T) {
	wire := Tuple{Source: Endpoint{IP: "192.0.2.1", Port: 40000}, Destination: Endpoint{IP: "192.0.2.2", Port: 502}, Transport: "tcp"}
	ds := Dataset{}
	ds.RecordLoss(CollectionLoss{Code: "capture_loss", Scope: LossScope{Source: Endpoint{IP: "198.51.100.1", Port: 1}, Destination: Endpoint{IP: "198.51.100.2", Port: 2}, Transport: "tcp", Ports: true}})
	for _, correlation := range []string{"wire", "verified", "unavailable"} {
		o := Observation{Source: SourceLive, ConnectionID: "unknown-aliases", Authority: Authority{Wire: wire, Correlation: correlation}}
		if !ds.LossTouches(o) {
			t.Fatalf("unproved alias disjointness accepted: %s", correlation)
		}
		o.Authority.Wire.Transport = "udp"
		if ds.LossTouches(o) {
			t.Fatalf("known transport disjointness was ignored: %s", correlation)
		}
	}
	// PCAP has only wire-coordinate authority and never invents conntrack NAT truth.
	if ds.LossTouches(Observation{Source: SourcePCAP, Authority: Authority{Wire: wire}}) {
		t.Fatal("unrelated offline wire lost usefulness")
	}
}

func TestWireAliasEnvelopeAuthority(t *testing.T) {
	wire := Tuple{Source: Endpoint{IP: "192.0.2.1", Port: 40000}, Destination: Endpoint{IP: "192.0.2.2", Port: 502}, Transport: "tcp"}
	for _, mode := range []string{"verified", "pcap", "unverified", "missing reply", "different wire", "different transport"} {
		o := observation()
		o.Source = SourceLive
		o.Authority = Authority{Wire: wire, Correlation: "verified", Aliases: &WireAliases{Original: wire, Reply: wire}}
		switch mode {
		case "pcap":
			o.Source = SourcePCAP
		case "unverified":
			o.Authority.Correlation = "wire"
		case "missing reply":
			o.Authority.Aliases.Reply = Tuple{}
		case "different wire":
			o.Authority.Wire.Source.IP = "198.51.100.1"
		case "different transport":
			o.Authority.Aliases.Reply.Transport = "udp"
		}
		if err := o.ValidateEnvelope(); (err == nil) != (mode == "verified") {
			t.Fatalf("mode=%s: %v", mode, err)
		}
	}
}
