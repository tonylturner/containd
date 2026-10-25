// SPDX-License-Identifier: Apache-2.0
package mgmtpath

import (
	"net/netip"
	"strings"
	"testing"
)

const example = `{"subnet":"10.99.99.0/24","sources":["10.99.99.10","10.99.99.3"],"listen":":8080"}`

func TestStrictDeclaration(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `{}`, example + ` {}`, strings.Replace(example, `"listen"`, `"Listen"`, 1), strings.Replace(example, `"listen":`, `"x":1,"listen":`, 1), strings.Replace(example, `"listen":`, `"listen":":8080","listen":`, 1), strings.Replace(example, `["10.99.99.10","10.99.99.3"]`, `null`, 1), strings.Replace(example, `10.99.99.3`, `192.0.2.3`, 1), strings.Replace(example, `10.99.99.3`, `10.99.99.10`, 1), strings.Replace(example, `10.99.99.0/24`, `::/0`, 1), strings.Replace(example, `:8080`, `:0`, 1), strings.Replace(example, `:8080`, `[::]:8080`, 1)} {
		if _, err := parse(raw); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	d, err := parse(example)
	if err != nil {
		t.Fatal(err)
	}
	nic1 := nic{name: "eth7", up: true, addresses: []netip.Prefix{netip.MustParsePrefix("10.99.99.2/24")}}
	for _, nics := range [][]nic{nil, {{name: "eth7", up: false, addresses: nic1.addresses}}, {nic1, nic1}} {
		if _, err := resolve(d, nics); err == nil {
			t.Errorf("accepted ambiguous/missing NIC %v", nics)
		}
	}
	r, err := resolve(d, []nic{nic1})
	if err != nil {
		t.Fatal(err)
	}
	if r.Device != "eth7" || r.Local.String() != "10.99.99.2/24" {
		t.Fatalf("lost boot identity: %+v", r)
	}
	for _, tc := range []struct {
		remote, local string
		want          bool
	}{{"10.99.99.10:32100", "10.99.99.2:8080", true}, {"10.99.99.3:32100", "10.99.99.2:8080", true}, {"10.99.99.4:32100", "10.99.99.2:8080", false}, {"10.99.99.10:32100", "10.99.99.2:8443", false}, {"10.99.99.10:32100", "192.0.2.2:8080", false}} {
		if got := r.Admits(netip.MustParseAddrPort(tc.remote), netip.MustParseAddrPort(tc.local)); got != tc.want {
			t.Errorf("%+v: %v", tc, got)
		}
	}
	if (*Reservation)(nil).Admits(netip.AddrPort{}, netip.AddrPort{}) {
		t.Fatal("nil admitted")
	}
}
func TestUnset(t *testing.T) {
	t.Setenv("CONTAIND_MGMT_RESERVATION", "")
	r, err := Load()
	if r != nil || err != nil {
		t.Fatal(r, err)
	}
}
func TestBindValidation(t *testing.T) {
	r := &Reservation{Local: netip.MustParsePrefix("10.99.99.2/24"), Port: 8080}
	for _, s := range []string{":8080", "0.0.0.0:8080", "10.99.99.2:8080"} {
		if err := r.ValidateListen(s); err != nil {
			t.Error(err)
		}
	}
	for _, s := range []string{":8443", "127.0.0.1:8080", "[::]:8080", "localhost:8080"} {
		if r.ValidateListen(s) == nil {
			t.Error(s)
		}
	}
	for _, s := range []string{"127.0.0.1:8081", "[::1]:8081"} {
		if err := r.ValidateEngineBind(s); err != nil {
			t.Error(err)
		}
	}
	for _, s := range []string{":8081", "0.0.0.0:8081", "localhost:8081"} {
		if r.ValidateEngineBind(s) == nil {
			t.Error(s)
		}
	}
}
