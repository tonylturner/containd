// SPDX-License-Identifier: Apache-2.0

package enforce

import "strings"

// nftKeywords are the words nft's scanner reads as keywords where a table
// name is expected: `add table inet <word>` is a syntax error for each of
// them, and quoting the name does not help. Matching is case-sensitive, as
// in nft: "Table" is a valid name, "table" is not.
var nftKeywords = func() map[string]struct{} {
	set := map[string]struct{}{}
	for _, w := range strings.Fields(nftKeywords111 + " " + nftKeywordsLater) {
		set[w] = struct{}{}
	}
	return set
}()

// nftKeywords111 are the keywords of nft 1.1.1.
const nftKeywords111 = `
accept add ah all and arp auto-merge bridge cgroup chain comment comp
constant continue counter cpu create ct day dccp define delete describe
destroy device devices dnat drop dst dup dynamic ecn element elements eq esp
ether exists expires export exthdr fib flags flow flowtable flush frag fwd
gc-interval ge geneve get goto gre gretap gt handle hbh hook hour ibriport
ibrname icmp icmpv6 igmp iif iifgroup iifname iiftype import include index
inet insert interval ip ip6 ipsec jhash jump le limit list log lshift lt map
mark masquerade meta meter mh missing monitor ne netdev nftrace not notrack
numgen obriport obrname offload oif oifgroup oifname oiftype or osf pkttype
policy position priority queue quota random redefine redirect reject rename
replace reset return rshift rt rt0 rt2 rtclassid rule ruleset sctp secmark
set size skgid skuid snat socket srh symhash synproxy table tcp th time
timeout tproxy type typeof udp udplite undefine update vlan vmap vni vxlan
xor xt
`

// nftKeywordsLater are the keywords later nft releases added, up to nft
// 1.1.7, the version the containd images ship.
const nftKeywordsLater = `tunnel`
