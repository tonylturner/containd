// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"
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

func (c *Compiler) writeRevocations(buf *bytes.Buffer) {
	for _, family := range []string{"4", "6"} {
		addr := "ipv" + family + "_addr"
		for _, service := range []bool{false, true} {
			name, typ := "revoke"+family, addr+" . "+addr+" . inet_proto . inet_service . inet_service"
			if service {
				name = "revoke_service" + family
				typ = addr + " . " + addr + " . inet_proto . inet_service"
			}
			fmt.Fprintf(buf, "  set %s {\n    type %s;\n    flags timeout;\n  }\n", name, typ)
		}
	}
	// Kernel-generated resets traverse OUTPUT with the rejected packet's
	// conntrack association. Let resets pass rather than rejecting our own RST.
	buf.WriteString("  chain revocations {\n    tcp flags & rst == rst return;\n")
	for _, family := range []string{"4", "6"} {
		ip := "ip"
		if family == "6" {
			ip = "ip6"
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
					fmt.Fprintf(buf, "    meta l4proto %s %s%s @%s %s;\n", proto, key, ports, name, action)
				}
			}
		}
	}
	buf.WriteString("  }\n  chain revocation_output {\n    type filter hook output priority 0; policy accept;\n    jump revocations;\n  }\n")
}

// RevokeConnections commits all keys atomically, before conntrack is deleted.
// Broad service keys use only original client addresses, never shared SNAT
// reply addresses. Reply tuples remain exact so other NAT clients stay live.
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
	if u.TableName == "" || sanitizeIdent(u.TableName) != u.TableName {
		return "", fmt.Errorf("invalid nft table name")
	}
	keys := map[string]bool{}
	for _, e := range entries {
		req := conntrack.KillRequest{DeleteRequest: conntrack.DeleteRequest{Proto: e.Proto, Src: e.Src, Dst: e.Dst}}
		req.Sport, _ = strconv.Atoi(e.Sport)
		req.Dport, _ = strconv.Atoi(e.Dport)
		if err := req.Validate(); err != nil {
			return "", err
		}
		family := "4"
		src, _ := netip.ParseAddr(req.Src)
		if src.Is6() {
			family = "6"
		}
		for _, tuple := range [][4]string{{e.Src, e.Dst, e.Sport, e.Dport}, {e.ReplySrc, e.ReplyDst, e.ReplySport, e.ReplyDport}} {
			a, ae := netip.ParseAddr(tuple[0])
			b, be := netip.ParseAddr(tuple[1])
			sp, se := strconv.Atoi(tuple[2])
			dp, de := strconv.Atoi(tuple[3])
			if ae != nil || be != nil || a.Is4() != src.Is4() || b.Is4() != src.Is4() || a.Zone() != "" || b.Zone() != "" || se != nil || de != nil || sp < 1 || sp > 65535 || dp < 1 || dp > 65535 {
				return "", fmt.Errorf("invalid revocation tuple")
			}
			key := fmt.Sprintf("%s . %s . %s . %d . %d", a, b, req.Proto, sp, dp)
			keys[fmt.Sprintf("add element inet %s revoke%s { %s timeout %ds }\n", u.TableName, family, key, int(ttl.Seconds()))] = true
		}
		if scope == "client-service" {
			key := fmt.Sprintf("%s . %s . %s . %d", req.Src, req.Dst, req.Proto, req.Dport)
			keys[fmt.Sprintf("add element inet %s revoke_service%s { %s timeout %ds }\n", u.TableName, family, key, int(ttl.Seconds()))] = true
		}
	}
	lines := make([]string, 0, len(keys))
	for key := range keys {
		lines = append(lines, key)
	}
	sort.Strings(lines)
	return strings.Join(lines, ""), nil
}
