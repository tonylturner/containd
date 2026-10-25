// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package ids

import (
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// convertSuricataConditions accounts for every constraint as it builds the
// executable subset. ContentMatches and header fields are export metadata, not
// predicates: merely storing a keyword does not make it evaluable.
func convertSuricataConditions(opts [][2]string, header suricataHeaderFields) (config.IDSCondition, []string) {
	var conds []config.IDSCondition
	var notes []string
	dropped := map[string]bool{}
	drop := func(keyword string) {
		if !dropped[keyword] {
			dropped[keyword] = true
			notes = append(notes, fmt.Sprintf("keyword %q not fully mapped", keyword))
		}
	}
	for _, field := range [][2]string{
		{"src_addr", header.srcAddr}, {"src_port", header.srcPort},
		{"dst_addr", header.dstAddr}, {"dst_port", header.dstPort},
	} {
		if field[1] != "any" {
			drop(field[0])
		}
	}

	var content string
	hasContent, mapped := false, false
	flush := func() {
		if hasContent && !mapped {
			drop("content")
		}
	}
	for _, opt := range opts {
		keyword, value := opt[0], opt[1]
		switch keyword {
		case "msg", "sid", "gid", "rev", "classtype", "priority", "reference", "metadata":
			// Descriptive options have no matching semantics.
		case "content":
			flush()
			content = unquote(value)
			hasContent, mapped = true, false
			// Negation, hex and escapes are preserved for export but are not
			// translated by the current string predicate converter.
			if content == "" || strings.HasPrefix(value, "!") || strings.ContainsAny(content, `|\`) {
				drop("content")
			}
		default:
			field, op := suricataBufferPredicate(keyword)
			if field == "" {
				// Includes flow, flowbits, pcre, byte_test, positional and
				// case modifiers, thresholds and unknown future keywords.
				drop(keyword)
				continue
			}
			if !hasContent || mapped {
				// Only the legacy content-then-buffer form is executable.
				// A sticky buffer before content must not silently disappear.
				drop(keyword)
				continue
			}
			conds = append(conds, config.IDSCondition{Field: field, Op: op, Value: content})
			mapped = true
		}
	}
	flush()
	switch len(conds) {
	case 0:
		return config.IDSCondition{}, notes
	case 1:
		return conds[0], notes
	default:
		return config.IDSCondition{All: conds}, notes
	}
}

func suricataBufferPredicate(keyword string) (string, string) {
	switch keyword {
	case "http_uri", "http.uri":
		return "attr.http_uri", "contains"
	case "http_header", "http.header":
		return "attr.http_header", "contains"
	case "http_method", "http.method":
		return "attr.http_method", "equals"
	case "dns_query", "dns.query":
		return "attr.dns_query", "contains"
	case "tls_sni", "tls.sni":
		return "attr.tls_sni", "contains"
	default:
		return "", ""
	}
}
