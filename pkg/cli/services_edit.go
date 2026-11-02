// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Keep untouched members as raw JSON, including integer limits and nested policy.
type serviceObject map[string]json.RawMessage
type serviceParser func(string) (any, error)
type serviceField struct {
	name  string
	path  string
	parse serviceParser
}

// File arguments keep credentials out of CLI history and command audit records.
func serviceSecretFile(path string) (any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read credential file: %w", err)
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	if value == "" {
		return nil, fmt.Errorf("credential file is empty")
	}
	return value, nil
}
func serviceKey(key, value string) (string, error) {
	if key != "mac" {
		return value, nil
	}
	mac, err := net.ParseMAC(value)
	if err != nil {
		return "", fmt.Errorf("invalid MAC address")
	}
	return mac.String(), nil
}
func serviceText(s string) (any, error) { return s, nil }
func serviceBool(s string) (any, error) {
	switch s {
	case "true", "on":
		return true, nil
	case "false", "off":
		return false, nil
	}
	return nil, fmt.Errorf("expected true|false (or on|off)")
}
func serviceInt(min, max int64) serviceParser {
	return func(s string) (any, error) {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < min || n > max {
			return nil, fmt.Errorf("expected integer %d..%d", min, max)
		}
		return n, nil
	}
}
func serviceEnum(values ...string) serviceParser {
	return func(s string) (any, error) {
		for _, v := range values {
			if s == v {
				return s, nil
			}
		}
		return nil, fmt.Errorf("expected %s", strings.Join(values, "|"))
	}
}
func serviceList(s string) (any, error) {
	if s == "-" {
		return []string{}, nil
	}
	list := strings.Split(s, ",")
	for i, v := range list {
		list[i] = strings.TrimSpace(v)
		if list[i] == "" {
			return nil, fmt.Errorf("empty list member; use - to clear the list")
		}
	}
	return list, nil
}
func serviceDuration(s string) (any, error) {
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return nil, fmt.Errorf("expected non-negative duration, for example 5m or 0s")
	}
	return int64(d), nil
}

func (o serviceObject) put(path string, value any) error {
	head, rest, nested := strings.Cut(path, ".")
	if nested {
		child := serviceObject{}
		if raw, ok := o[head]; ok && string(raw) != "null" {
			if err := json.Unmarshal(raw, &child); err != nil {
				return fmt.Errorf("invalid %s: %w", head, err)
			}
		}
		if child == nil {
			child = serviceObject{}
		}
		if err := child.put(rest, value); err != nil {
			return err
		}
		value = child
	}
	raw, err := json.Marshal(value)
	if err == nil {
		o[head] = raw
	}
	return err
}
func (o serviceObject) collection(path string) ([]serviceObject, error) {
	head, rest, nested := strings.Cut(path, ".")
	raw, exists := o[head]
	if !exists || string(raw) == "null" {
		return nil, nil
	}
	if nested {
		var child serviceObject
		if err := json.Unmarshal(raw, &child); err != nil {
			return nil, err
		}
		return child.collection(rest)
	}
	var items []serviceObject
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, err
	}
	for _, item := range items {
		if item == nil {
			return nil, fmt.Errorf("invalid null collection member")
		}
	}
	return items, nil
}
func editService(api *API, endpoint string, edit func(serviceObject) error) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		current := serviceObject{}
		revision, err := api.getConfigJSON(ctx, endpoint, &current)
		if err != nil {
			return err
		}
		if err := edit(current); err != nil {
			return err
		}
		return api.saveJSON(ctx, endpoint, current, revision, out)
	}
}
func registerServiceFields(r *Registry, api *API, prefix, endpoint string, fields []serviceField) {
	for _, field := range fields {
		name := "set " + prefix + " " + field.name
		r.RegisterRole(name, RoleAdmin, func(ctx context.Context, out io.Writer, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("usage: %s <value> (lists: comma-separated, - clears)", name)
			}
			// Credential *-file fields read caller-supplied paths before any
			// candidate API call. Web commands must never reach that parser.
			if strings.HasSuffix(field.name, "-file") {
				if err := requireLocalFilesystem(ctx); err != nil {
					return err
				}
			}
			value, err := field.parse(args[0])
			if err != nil {
				return fmt.Errorf("%s: %w", field.name, err)
			}
			return editService(api, endpoint, func(o serviceObject) error { return o.put(field.path, value) })(ctx, out, nil)
		})
	}
}

// Collection edits address stable keys, or a one-based candidate index for
// scan selections. Add never overwrites; set/delete require an existing entry.
type serviceCollection struct {
	name, endpoint, path string
	keys                 []string
	fields               []serviceField
	required             []string
	defaults             serviceObject
}

func registerServiceCollection(r *Registry, api *API, c serviceCollection) {
	for _, action := range []string{"add", "set", "delete"} {
		name := action + " " + c.name
		r.RegisterRole(name, RoleAdmin, serviceCollectionCommand(api, c, action))
	}
}
func serviceCollectionCommand(api *API, c serviceCollection, action string) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		keyCount := len(c.keys)
		if keyCount == 0 && action != "add" {
			keyCount = 1
		}
		keyNames := c.keys
		if len(keyNames) == 0 && action != "add" {
			keyNames = []string{"index"}
		}
		syntax := action + " " + c.name
		for _, key := range keyNames {
			syntax += " <" + key + ">"
		}
		if action != "delete" {
			syntax += " [--field value ...]; fields: " + serviceFieldNames(c.fields)
		}
		usage := fmt.Errorf("usage: %s", syntax)
		if len(args) < keyCount || (action == "delete" && len(args) != keyCount) {
			return usage
		}
		keys := append([]string{}, args[:keyCount]...)
		for i, key := range c.keys {
			value, err := serviceKey(key, keys[i])
			if err != nil {
				return err
			}
			keys[i] = value
		}
		for _, key := range keys {
			if strings.TrimSpace(key) == "" {
				return usage
			}
		}
		patch := serviceObject{}
		options := args[keyCount:]
		if len(options)%2 != 0 || (action == "set" && len(options) == 0) {
			return usage
		}
		seen := map[string]bool{}
		for i := 0; i < len(options); i += 2 {
			fieldName := strings.TrimPrefix(options[i], "--")
			if !strings.HasPrefix(options[i], "--") || seen[fieldName] {
				return usage
			}
			seen[fieldName] = true
			var field *serviceField
			for j := range c.fields {
				if c.fields[j].name == fieldName {
					field = &c.fields[j]
					break
				}
			}
			if field == nil {
				return usage
			}
			value, err := field.parse(options[i+1])
			if err != nil {
				return fmt.Errorf("%s: %w", fieldName, err)
			}
			if err := patch.put(field.path, value); err != nil {
				return err
			}
		}
		if action == "add" {
			for _, required := range c.required {
				if !seen[required] {
					return fmt.Errorf("--%s required", required)
				}
			}
		}
		return editService(api, c.endpoint, func(o serviceObject) error {
			items, err := o.collection(c.path)
			if err != nil {
				return err
			}
			index := -1
			if len(c.keys) == 0 && action != "add" {
				n, err := strconv.Atoi(keys[0])
				if err != nil || n < 1 || n > len(items) {
					return fmt.Errorf("unknown %s index %q", c.name, keys[0])
				}
				index = n - 1
			} else if len(c.keys) > 0 {
				for i, item := range items {
					match := true
					for j, key := range c.keys {
						var v string
						if err := json.Unmarshal(item[key], &v); err != nil {
							return err
						}
						normalized, err := serviceKey(key, v)
						if err != nil {
							return err
						}
						if normalized != keys[j] {
							match = false
						}
					}
					if match {
						if index >= 0 {
							return fmt.Errorf("ambiguous %s key", c.name)
						}
						index = i
					}
				}
			}
			switch action {
			case "add":
				if index >= 0 {
					return fmt.Errorf("%s already exists; use set", c.name)
				}
				item := serviceObject{}
				for k, v := range c.defaults {
					item[k] = v
				}
				for i, key := range c.keys {
					if err := item.put(key, keys[i]); err != nil {
						return err
					}
				}
				for k, v := range patch {
					item[k] = v
				}
				items = append(items, item)
			case "set":
				if index < 0 {
					return fmt.Errorf("%s not found", c.name)
				}
				for k, v := range patch {
					items[index][k] = v
				}
			case "delete":
				if index < 0 {
					return fmt.Errorf("%s not found", c.name)
				}
				items = append(items[:index], items[index+1:]...)
			}
			if items == nil {
				items = []serviceObject{}
			}
			return o.put(c.path, items)
		})(ctx, out, nil)
	}
}
func serviceFieldNames(fields []serviceField) string {
	names := make([]string, len(fields))
	for i, f := range fields {
		names[i] = "--" + f.name
	}
	return strings.Join(names, ", ")
}
