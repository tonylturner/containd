// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
)

// ConnectionRevoker is distinct from the DPI block updater: revocations need
// exact, bidirectional, NAT-aware tuples and active TCP rejection.
type ConnectionRevoker interface {
	RevokeConnections(context.Context, []conntrack.Entry, string, time.Duration) error
}

// revocationSets returns the revocation sets. The ICMP sets key packets
// without conntrack state by the ICMP identifier, which only a typeof set
// accepts: nft types icmp id as a plain integer.
func revocationSets() []dynamicSet {
	var sets []dynamicSet
	for _, family := range []string{"4", "6"} {
		addr := "ipv" + family + "_addr"
		ip, icmp := "ip", "icmp"
		if family == "6" {
			ip, icmp = "ip6", "icmpv6"
		}
		sets = append(sets,
			dynamicSet{name: "revoke" + family, key: addr + " . " + addr + " . inet_proto . inet_service . inet_service"},
			dynamicSet{name: "revoke_service" + family, key: addr + " . " + addr + " . inet_proto . inet_service"},
			dynamicSet{name: "revoke_icmp" + family, key: "typeof " + ip + " saddr . " + ip + " daddr . " + icmp + " id", datatypes: addr + " . " + addr + " . integer"})
	}
	return sets
}

// revocationRules returns the rules of the revocations chain.
func revocationRules() []string {
	// Kernel-generated resets traverse OUTPUT with the rejected packet's
	// conntrack association. Let resets pass rather than rejecting our own RST.
	out := []string{"tcp flags & rst == rst return"}
	for _, family := range []string{"4", "6"} {
		ip, icmp := "ip", "icmp"
		if family == "6" {
			ip, icmp = "ip6", "icmpv6"
		}
		for _, service := range []bool{false, true} {
			name := "revoke" + family
			if service {
				name = "revoke_service" + family
			}
			for _, ct := range []bool{false, true} {
				// Raw keys are only for packets without usable conntrack state.
				// A later NAT connection may reuse a revoked reply port; its
				// own original tuple, not that translated packet, is authority.
				key := "ct state { invalid, untracked } " + ip + " saddr . " + ip + " daddr . meta l4proto . "
				ports := "th sport . th dport"
				if service {
					ports = "th dport"
				}
				if ct {
					key = "ct original " + ip + " saddr . ct original " + ip + " daddr . meta l4proto . "
					ports = "ct original proto-src . ct original proto-dst"
					if service {
						ports = "ct original proto-dst"
					}
				}
				for _, proto := range []string{"tcp", "udp"} {
					action := "drop"
					if proto == "tcp" {
						action = "reject with tcp reset"
					}
					out = append(out, fmt.Sprintf("meta l4proto %s %s%s @%s %s", proto, key, ports, name, action))
				}
			}
			out = append(out, icmpRevocationRules(family, ip, icmp, name, service)...)
		}
	}
	return out
}

// icmpRevocationRules drop the ICMP (IPv4) or ICMPv6 (IPv6) packets of
// revoked entries. In an ICMP tuple the identifier takes the source port's
// place (ct original proto-src) and the query type and code the destination
// port's (ct original proto-dst, type * 256 + code). The tracked rules
// require an ICMP entry: an ICMP error travels with the entry of the flow it
// reports on, so errors about TCP and UDP flows never match an ICMP
// revocation.
//
// Packets without conntrack state, exempted by notrack or arriving after
// their entry was deleted, match the service key by their own type and code
// (th sport, the first two bytes of the ICMP header), and the exact key by
// their addresses and identifier in revoke_icmp<family>. nft matches the
// identifier of echo requests and replies only, so other untracked query
// types escape an exact revocation.
func icmpRevocationRules(family, ip, proto, set string, service bool) []string {
	untracked := "meta l4proto " + proto + " ct state { invalid, untracked } " + ip + " saddr . " + ip + " daddr . "
	tracked := "ct original proto-src . ct original proto-dst"
	raw := fmt.Sprintf("%s%s id @revoke_icmp%s drop", untracked, proto, family)
	if service {
		tracked = "ct original proto-dst"
		raw = fmt.Sprintf("%smeta l4proto . th sport @%s drop", untracked, set)
	}
	return []string{raw, fmt.Sprintf("meta l4proto %s ct protocol %s ct original %s saddr . ct original %s daddr . meta l4proto . %s @%s drop", proto, proto, ip, ip, tracked, set)}
}

// RevokeConnections commits all keys atomically, before conntrack is deleted.
// Broad service keys use only original client addresses, never shared SNAT
// reply addresses. Reply tuples remain exact so other NAT clients stay live.
// Tracked ICMP and ICMPv6 packets match the original tuple in both
// directions; untracked ones match the identifier of either tuple.
func (u *NftUpdater) RevokeConnections(ctx context.Context, entries []conntrack.Entry, scope string, ttl time.Duration) error {
	text, err := u.revocationBatch(entries, scope, ttl)
	if err != nil {
		return err
	}
	return (&NftApplier{Path: u.Path}).Apply(ctx, text)
}

func (u *NftUpdater) revocationBatch(entries []conntrack.Entry, scope string, ttl time.Duration) (string, error) {
	if scope != "connection" && scope != "client-service" {
		return "", fmt.Errorf("invalid revocation scope")
	}
	if ttl < time.Second || ttl > time.Hour || ttl%time.Second != 0 || len(entries) == 0 {
		return "", fmt.Errorf("revocation needs entries and a 1–3600 second interval")
	}
	if err := ValidateTableName(u.TableName); err != nil {
		return "", err
	}
	keys := map[string]bool{}
	add := func(set, key string) {
		keys[fmt.Sprintf("add element inet %s %s { %s timeout %ds }\n", u.TableName, set, key, int(ttl.Seconds()))] = true
	}
	for _, e := range entries {
		original, err := e.Original()
		if err != nil {
			return "", err
		}
		req := conntrack.KillRequest{DeleteRequest: original}
		if err := req.Validate(); err != nil {
			return "", err
		}
		family := "4"
		src, _ := netip.ParseAddr(req.Src)
		if src.Is6() {
			family = "6"
		}
		if conntrack.IsICMP(req.Proto) {
			typeCode := req.ICMPType<<8 | req.ICMPCode
			add("revoke"+family, fmt.Sprintf("%s . %s . %s . %d . %d", req.Src, req.Dst, req.Proto, req.ICMPID, typeCode))
			for _, tuple := range [][3]string{{e.Src, e.Dst, e.ICMPID}, {e.ReplySrc, e.ReplyDst, e.ReplyICMPID}} {
				a, b, err := tupleAddrs(tuple[0], tuple[1], src.Is4())
				id, ie := strconv.ParseUint(tuple[2], 10, 16)
				if err != nil || ie != nil {
					return "", fmt.Errorf("invalid revocation tuple")
				}
				add("revoke_icmp"+family, fmt.Sprintf("%s . %s . %d", a, b, id))
			}
			if scope == "client-service" {
				add("revoke_service"+family, fmt.Sprintf("%s . %s . %s . %d", req.Src, req.Dst, req.Proto, typeCode))
			}
			continue
		}
		for _, tuple := range [][4]string{{e.Src, e.Dst, e.Sport, e.Dport}, {e.ReplySrc, e.ReplyDst, e.ReplySport, e.ReplyDport}} {
			a, b, err := tupleAddrs(tuple[0], tuple[1], src.Is4())
			sp, se := strconv.Atoi(tuple[2])
			dp, de := strconv.Atoi(tuple[3])
			if err != nil || se != nil || de != nil || sp < 1 || sp > 65535 || dp < 1 || dp > 65535 {
				return "", fmt.Errorf("invalid revocation tuple")
			}
			add("revoke"+family, fmt.Sprintf("%s . %s . %s . %d . %d", a, b, req.Proto, sp, dp))
		}
		if scope == "client-service" {
			add("revoke_service"+family, fmt.Sprintf("%s . %s . %s . %d", req.Src, req.Dst, req.Proto, req.Dport))
		}
	}
	lines := make([]string, 0, len(keys))
	for key := range keys {
		lines = append(lines, key)
	}
	sort.Strings(lines)
	return strings.Join(lines, ""), nil
}

// tupleAddrs parses the addresses of one tuple direction, which must be of
// the entry's family (IPv4 when v4) and carry no zone.
func tupleAddrs(src, dst string, v4 bool) (netip.Addr, netip.Addr, error) {
	a, ae := netip.ParseAddr(src)
	b, be := netip.ParseAddr(dst)
	if ae != nil || be != nil || a.Is4() != v4 || b.Is4() != v4 || a.Zone() != "" || b.Zone() != "" {
		return a, b, fmt.Errorf("invalid revocation tuple")
	}
	return a, b, nil
}
