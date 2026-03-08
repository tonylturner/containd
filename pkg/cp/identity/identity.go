// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package identity

import (
	"net"
	"sync"
)

// Placeholder identity model types.

type User struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles,omitempty"`
}

type Device struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Session struct {
	UserID   string `json:"userId"`
	DeviceID string `json:"deviceId"`
	IP       string `json:"ip"`
}

// Mapping represents an IP-to-identity mapping for API serialization.
type Mapping struct {
	IP         string   `json:"ip"`
	Identities []string `json:"identities"`
}

// Resolver provides a thread-safe mapping from IP addresses to identity names.
// Mappings are registered manually; DHCP lease integration comes later.
type Resolver struct {
	mu       sync.RWMutex
	mappings map[string][]string // key: IP string (canonical form)
}

// NewResolver creates a new empty Resolver.
func NewResolver() *Resolver {
	return &Resolver{
		mappings: make(map[string][]string),
	}
}

// Register adds or replaces the identity mapping for the given IP.
func (r *Resolver) Register(ip net.IP, identities []string) {
	key := ip.String()
	cp := make([]string, len(identities))
	copy(cp, identities)
	r.mu.Lock()
	r.mappings[key] = cp
	r.mu.Unlock()
}

// Remove deletes the identity mapping for the given IP.
func (r *Resolver) Remove(ip net.IP) {
	key := ip.String()
	r.mu.Lock()
	delete(r.mappings, key)
	r.mu.Unlock()
}

// Resolve returns the identities associated with the given IP, or nil if none.
func (r *Resolver) Resolve(ip net.IP) []string {
	key := ip.String()
	r.mu.RLock()
	ids := r.mappings[key]
	r.mu.RUnlock()
	if len(ids) == 0 {
		return nil
	}
	cp := make([]string, len(ids))
	copy(cp, ids)
	return cp
}

// All returns all current IP-to-identity mappings.
func (r *Resolver) All() []Mapping {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Mapping, 0, len(r.mappings))
	for ip, ids := range r.mappings {
		cp := make([]string, len(ids))
		copy(cp, ids)
		out = append(out, Mapping{IP: ip, Identities: cp})
	}
	return out
}
