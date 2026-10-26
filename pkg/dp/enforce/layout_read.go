// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// objectKinds maps the JSON key of each named nft object to the keyword
// that deletes it.
var objectKinds = map[string]string{
	"set": "set", "map": "map", "flowtable": "flowtable", "counter": "counter", "quota": "quota",
	"limit": "limit", "secmark": "secmark", "synproxy": "synproxy",
	"ct helper": "ct helper", "ct timeout": "ct timeout", "ct expectation": "ct expectation",
}

// ReadTable reads the layout of inet table, which need not exist. The
// elements of a legacy block_flows set are read too, to carry them over.
func (a *NftApplier) ReadTable(ctx context.Context, table string) (TableLayout, error) {
	if err := ValidateTableName(table); err != nil {
		return TableLayout{}, err
	}
	tables, err := a.list(ctx, "list", "tables")
	if err != nil {
		return TableLayout{}, err
	}
	exists, err := hasInetTable(tables, table)
	if err != nil || !exists {
		return TableLayout{}, err
	}
	listing, err := a.list(ctx, "-t", "list", "table", "inet", table)
	if err != nil {
		return TableLayout{}, err
	}
	layout, err := parseTableLayout(listing)
	if err != nil {
		return TableLayout{}, err
	}
	for _, obj := range layout.Objects {
		if obj.Kind == "set" && obj.Name == "block_flows" && obj.Type == legacyFlowType {
			set, err := a.list(ctx, "list", "set", "inet", table, "block_flows")
			if err != nil {
				return TableLayout{}, err
			}
			if layout.LegacyFlowBlocks, err = parseLegacyFlowBlocks(set); err != nil {
				return TableLayout{}, err
			}
		}
	}
	return layout, nil
}

// list runs an nft JSON listing command.
func (a *NftApplier) list(ctx context.Context, args ...string) ([]byte, error) {
	path := a.Path
	if path == "" {
		path = "nft"
	}
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(ctx, path, append([]string{"-j"}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("nft %s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// nftItems decodes the item list of an nft JSON document: one single-key
// object per item.
func nftItems(doc []byte) ([]map[string]json.RawMessage, error) {
	var out struct {
		Items []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(doc, &out); err != nil {
		return nil, fmt.Errorf("decode nft listing: %w", err)
	}
	return out.Items, nil
}

func hasInetTable(doc []byte, name string) (bool, error) {
	items, err := nftItems(doc)
	if err != nil {
		return false, err
	}
	for _, item := range items {
		var t struct{ Family, Name string }
		if raw, ok := item["table"]; ok {
			if err := json.Unmarshal(raw, &t); err != nil {
				return false, fmt.Errorf("decode nft table: %w", err)
			}
			if t.Family == "inet" && t.Name == name {
				return true, nil
			}
		}
	}
	return false, nil
}

func parseTableLayout(doc []byte) (TableLayout, error) {
	items, err := nftItems(doc)
	if err != nil {
		return TableLayout{}, err
	}
	layout := TableLayout{Exists: true}
	for _, item := range items {
		for key, raw := range item {
			switch key {
			case "metainfo", "table", "rule", "element":
			case "chain":
				var ch LiveChain
				if err := json.Unmarshal(raw, &ch); err != nil {
					return TableLayout{}, fmt.Errorf("decode nft chain: %w", err)
				}
				layout.Chains = append(layout.Chains, ch)
			default:
				kind, ok := objectKinds[key]
				if !ok {
					return TableLayout{}, fmt.Errorf("unsupported nft object %q in the dynamic table", key)
				}
				var obj struct {
					Name  string
					Type  json.RawMessage
					Flags json.RawMessage
				}
				if err := json.Unmarshal(raw, &obj); err != nil {
					return TableLayout{}, fmt.Errorf("decode nft %s: %w", key, err)
				}
				typ, flags := stringList(obj.Type), stringList(obj.Flags)
				sort.Strings(flags)
				layout.Objects = append(layout.Objects, LiveObject{Kind: kind, Name: obj.Name, Type: strings.Join(typ, " . "), Flags: flags})
			}
		}
	}
	return layout, nil
}

// stringList decodes an nft JSON value that is a string or a string array.
// Any other value (such as a typeof expression) is kept as its raw text,
// which never matches the current layout.
func stringList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	return []string{string(raw)}
}

// parseLegacyFlowBlocks translates the elements of a legacy block_flows set
// (source . destination . port, which matched TCP and UDP) into elements of
// the current type, one "tcp, udp" pair per legacy element. Elements about
// to expire are dropped; elements containd could not have written are
// rejected.
func parseLegacyFlowBlocks(doc []byte) ([]string, error) {
	items, err := nftItems(doc)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, item := range items {
		raw, ok := item["set"]
		if !ok {
			continue
		}
		var set struct{ Elem []json.RawMessage }
		if err := json.Unmarshal(raw, &set); err != nil {
			return nil, fmt.Errorf("decode nft set: %w", err)
		}
		for _, e := range set.Elem {
			elems, err := legacyFlowBlock(e)
			if err != nil {
				return nil, err
			}
			if elems != "" {
				out = append(out, elems)
			}
		}
	}
	return out, nil
}

func legacyFlowBlock(raw json.RawMessage) (string, error) {
	var wrapped struct {
		Elem *struct {
			Val     json.RawMessage
			Timeout *int
			Expires *int
		}
	}
	val := raw
	timeout := ""
	if err := json.Unmarshal(raw, &wrapped); err == nil && wrapped.Elem != nil {
		val = wrapped.Elem.Val
		if wrapped.Elem.Timeout != nil {
			if wrapped.Elem.Expires == nil || *wrapped.Elem.Expires < 1 {
				return "", nil
			}
			timeout = fmt.Sprintf(" timeout %ds", *wrapped.Elem.Expires)
		}
	}
	var key struct{ Concat []json.RawMessage }
	if err := json.Unmarshal(val, &key); err != nil || len(key.Concat) != 3 {
		return "", fmt.Errorf("unexpected legacy block_flows element %s", raw)
	}
	var src, dst string
	if json.Unmarshal(key.Concat[0], &src) != nil || json.Unmarshal(key.Concat[1], &dst) != nil {
		return "", fmt.Errorf("unexpected legacy block_flows element %s", raw)
	}
	s, serr := netip.ParseAddr(src)
	d, derr := netip.ParseAddr(dst)
	port, perr := strconv.Atoi(strings.Trim(string(key.Concat[2]), `"`))
	if serr != nil || derr != nil || !s.Is4() || !d.Is4() || perr != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("unexpected legacy block_flows element %s", raw)
	}
	return fmt.Sprintf("%s . %s . tcp . %d%s, %s . %s . udp . %d%s", s, d, port, timeout, s, d, port, timeout), nil
}
