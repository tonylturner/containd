// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package pcap

import "time"

type Status struct {
	Running    bool      `json:"running"`
	Interfaces []string  `json:"interfaces,omitempty"`
	StartedAt  time.Time `json:"startedAt,omitempty"`
	LastError  string    `json:"lastError,omitempty"`
}

type Item struct {
	Name      string    `json:"name"`
	Interface string    `json:"interface"`
	SizeBytes int64     `json:"sizeBytes"`
	CreatedAt time.Time `json:"createdAt"`
	Tags      []string  `json:"tags,omitempty"`
	Status    string    `json:"status,omitempty"`
}

type ReplayRequest struct {
	Name      string `json:"name"`
	Interface string `json:"interface"`
	RatePPS   int    `json:"ratePps,omitempty"`
}

type TagRequest struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}
