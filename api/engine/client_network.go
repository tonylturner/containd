// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
)

type blockHostRequest struct {
	IP         string `json:"ip"`
	TTLSeconds int    `json:"ttlSeconds,omitempty"`
}

type blockFlowRequest struct {
	SrcIP      string `json:"srcIp"`
	DstIP      string `json:"dstIp"`
	Proto      string `json:"proto"`
	DstPort    string `json:"dstPort"`
	TTLSeconds int    `json:"ttlSeconds,omitempty"`
}

func (c *HTTPClient) ConfigureInterfaces(ctx context.Context, ifaces []config.Interface) error {
	if c.BaseURL == "" {
		return fmt.Errorf("engine BaseURL is empty")
	}
	body, err := json.Marshal(ifaces)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/interfaces", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return engineStatusError(resp, "engine interfaces status")
	}
	return nil
}

func (c *HTTPClient) ConfigureInterfacesReplace(ctx context.Context, ifaces []config.Interface) error {
	if c.BaseURL == "" {
		return fmt.Errorf("engine BaseURL is empty")
	}
	body, err := json.Marshal(ifaces)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/interfaces?mode=replace", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return engineStatusError(resp, "engine interfaces(replace) status")
	}
	return nil
}

func (c *HTTPClient) ConfigureRouting(ctx context.Context, routing config.RoutingConfig) error {
	if c.BaseURL == "" {
		return fmt.Errorf("engine BaseURL is empty")
	}
	body, err := json.Marshal(routing)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/routing", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return engineStatusError(resp, "engine routing status")
	}
	return nil
}

func (c *HTTPClient) ConfigureRoutingReplace(ctx context.Context, routing config.RoutingConfig) error {
	if c.BaseURL == "" {
		return fmt.Errorf("engine BaseURL is empty")
	}
	body, err := json.Marshal(routing)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/routing?mode=replace", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return engineStatusError(resp, "engine routing(replace) status")
	}
	return nil
}

func (c *HTTPClient) BlockHostTemp(ctx context.Context, ip net.IP, ttl time.Duration) error {
	if c.BaseURL == "" {
		return fmt.Errorf("engine BaseURL is empty")
	}
	if ip == nil {
		return fmt.Errorf("ip is nil")
	}
	reqBody := blockHostRequest{IP: ip.String()}
	if ttl > 0 {
		reqBody.TTLSeconds = int(ttl.Seconds())
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/blocks/host", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("engine block host status %d", resp.StatusCode)
	}
	return nil
}

func (c *HTTPClient) BlockFlowTemp(ctx context.Context, srcIP, dstIP net.IP, proto string, dport string, ttl time.Duration) error {
	if c.BaseURL == "" {
		return fmt.Errorf("engine BaseURL is empty")
	}
	if srcIP == nil || dstIP == nil {
		return fmt.Errorf("src/dst ip required")
	}
	reqBody := blockFlowRequest{
		SrcIP:   srcIP.String(),
		DstIP:   dstIP.String(),
		Proto:   proto,
		DstPort: dport,
	}
	if ttl > 0 {
		reqBody.TTLSeconds = int(ttl.Seconds())
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/blocks/flow", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("engine block flow status %d", resp.StatusCode)
	}
	return nil
}

func (c *HTTPClient) GetWireGuardStatus(ctx context.Context, iface string) (netcfg.WireGuardStatus, error) {
	if c.BaseURL == "" {
		return netcfg.WireGuardStatus{}, fmt.Errorf("engine BaseURL is empty")
	}
	u := c.BaseURL + "/internal/wireguard/status"
	if strings.TrimSpace(iface) != "" {
		u += "?iface=" + url.QueryEscape(strings.TrimSpace(iface))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return netcfg.WireGuardStatus{}, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return netcfg.WireGuardStatus{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return netcfg.WireGuardStatus{}, engineStatusError(resp, "engine wireguard status")
	}
	var out netcfg.WireGuardStatus
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return netcfg.WireGuardStatus{}, err
	}
	return out, nil
}

func (c *HTTPClient) ListInterfaceState(ctx context.Context) ([]config.InterfaceState, error) {
	if c.BaseURL == "" {
		return nil, fmt.Errorf("engine BaseURL is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/internal/interfaces/state", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("engine interfaces state status %d", resp.StatusCode)
	}
	var out []config.InterfaceState
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}
