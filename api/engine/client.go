// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dhcpd"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
	"github.com/tonylturner/containd/pkg/dp/pcap"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// HTTPClient applies runtime config and snapshots to the engine via internal HTTP.
type HTTPClient struct {
	BaseURL string
	Client  *http.Client
}

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

func NewHTTPClient(baseURL string) *HTTPClient {
	return &HTTPClient{
		BaseURL: baseURL,
		Client:  &http.Client{Timeout: 5 * time.Second},
	}
}

func engineStatusError(resp *http.Response, prefix string) error {
	body, _ := io.ReadAll(resp.Body)
	detail := strings.TrimSpace(string(body))
	if detail == "" {
		return fmt.Errorf("%s %d", prefix, resp.StatusCode)
	}
	return fmt.Errorf("%s %d: %s", prefix, resp.StatusCode, detail)
}

func (c *HTTPClient) ApplyRules(ctx context.Context, snap rules.Snapshot) error {
	if c.BaseURL == "" {
		return fmt.Errorf("engine BaseURL is empty")
	}
	body, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/apply_rules", bytes.NewReader(body))
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
		return engineStatusError(resp, "engine apply_rules status")
	}
	return nil
}

func (c *HTTPClient) Configure(ctx context.Context, cfg config.DataPlaneConfig) error {
	if c.BaseURL == "" {
		return fmt.Errorf("engine BaseURL is empty")
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/config", bytes.NewReader(body))
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
		return fmt.Errorf("engine config status %d", resp.StatusCode)
	}
	return nil
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

func (c *HTTPClient) ConfigureServices(ctx context.Context, services config.ServicesConfig) error {
	if c.BaseURL == "" {
		return fmt.Errorf("engine BaseURL is empty")
	}
	body, err := json.Marshal(services)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/services", bytes.NewReader(body))
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
		b, _ := io.ReadAll(resp.Body)
		detail := strings.TrimSpace(string(b))
		if detail != "" {
			return fmt.Errorf("engine services status %d: %s", resp.StatusCode, detail)
		}
		return fmt.Errorf("engine services status %d", resp.StatusCode)
	}
	return nil
}

func (c *HTTPClient) PcapConfig(ctx context.Context) (config.PCAPConfig, error) {
	var out config.PCAPConfig
	if c.BaseURL == "" {
		return out, fmt.Errorf("engine BaseURL is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/internal/pcap/config", nil)
	if err != nil {
		return out, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return out, engineStatusError(resp, "engine pcap config status")
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *HTTPClient) SetPcapConfig(ctx context.Context, cfg config.PCAPConfig) (config.PCAPConfig, error) {
	var out config.PCAPConfig
	if c.BaseURL == "" {
		return out, fmt.Errorf("engine BaseURL is empty")
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/pcap/config", bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return out, fmt.Errorf("engine pcap config status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *HTTPClient) StartPcap(ctx context.Context, cfg config.PCAPConfig) (pcap.Status, error) {
	var out pcap.Status
	if c.BaseURL == "" {
		return out, fmt.Errorf("engine BaseURL is empty")
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/pcap/start", bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return out, engineStatusError(resp, "engine pcap start status")
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *HTTPClient) StopPcap(ctx context.Context) (pcap.Status, error) {
	var out pcap.Status
	if c.BaseURL == "" {
		return out, fmt.Errorf("engine BaseURL is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/pcap/stop", nil)
	if err != nil {
		return out, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return out, engineStatusError(resp, "engine pcap stop status")
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *HTTPClient) PcapStatus(ctx context.Context) (pcap.Status, error) {
	var out pcap.Status
	if c.BaseURL == "" {
		return out, fmt.Errorf("engine BaseURL is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/internal/pcap/status", nil)
	if err != nil {
		return out, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return out, fmt.Errorf("engine pcap status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *HTTPClient) ListPcaps(ctx context.Context) ([]pcap.Item, error) {
	if c.BaseURL == "" {
		return nil, fmt.Errorf("engine BaseURL is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/internal/pcap/list", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("engine pcap list status %d", resp.StatusCode)
	}
	var out []pcap.Item
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *HTTPClient) UploadPcap(ctx context.Context, filename string, r io.Reader) (pcap.Item, error) {
	var out pcap.Item
	if c.BaseURL == "" {
		return out, fmt.Errorf("engine BaseURL is empty")
	}
	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)
	go func() {
		part, err := writer.CreateFormFile("file", filename)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if _, err := io.Copy(part, r); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if err := writer.Close(); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_ = pw.Close()
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/pcap/upload", pr)
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := c.Client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return out, fmt.Errorf("engine pcap upload status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *HTTPClient) DeletePcap(ctx context.Context, name string) error {
	if c.BaseURL == "" {
		return fmt.Errorf("engine BaseURL is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.BaseURL+"/internal/pcap/delete?name="+url.QueryEscape(name), nil)
	if err != nil {
		return err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("engine pcap delete status %d", resp.StatusCode)
	}
	return nil
}

func (c *HTTPClient) TagPcap(ctx context.Context, req pcap.TagRequest) error {
	if c.BaseURL == "" {
		return fmt.Errorf("engine BaseURL is empty")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/pcap/tag", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("engine pcap tag status %d", resp.StatusCode)
	}
	return nil
}

func (c *HTTPClient) ReplayPcap(ctx context.Context, req pcap.ReplayRequest) error {
	if c.BaseURL == "" {
		return fmt.Errorf("engine BaseURL is empty")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/pcap/replay", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("engine pcap replay status %d", resp.StatusCode)
	}
	return nil
}

func (c *HTTPClient) DownloadPcap(ctx context.Context, name string) (*http.Response, error) {
	if c.BaseURL == "" {
		return nil, fmt.Errorf("engine BaseURL is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/internal/pcap/download?name="+url.QueryEscape(name), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, fmt.Errorf("engine pcap download status %d", resp.StatusCode)
	}
	return resp, nil
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
		b, _ := io.ReadAll(resp.Body)
		detail := strings.TrimSpace(string(b))
		if detail != "" {
			return netcfg.WireGuardStatus{}, fmt.Errorf("engine wireguard status %d: %s", resp.StatusCode, detail)
		}
		return netcfg.WireGuardStatus{}, fmt.Errorf("engine wireguard status %d", resp.StatusCode)
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

// ListEvents fetches recent normalized events from the engine.
func (c *HTTPClient) ListEvents(ctx context.Context, limit int) ([]dpevents.Event, error) {
	u := c.BaseURL + "/internal/events"
	if limit > 0 {
		u += "?limit=" + url.QueryEscape(fmt.Sprintf("%d", limit))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("engine events status %d", resp.StatusCode)
	}
	var out []dpevents.Event
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *HTTPClient) ListConntrack(ctx context.Context, limit int) ([]conntrack.Entry, error) {
	u := c.BaseURL + "/internal/conntrack"
	if limit > 0 {
		u += "?limit=" + url.QueryEscape(fmt.Sprintf("%d", limit))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("engine conntrack status %d", resp.StatusCode)
	}
	var out struct {
		Entries []conntrack.Entry `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Entries == nil {
		return []conntrack.Entry{}, nil
	}
	return out.Entries, nil
}

func (c *HTTPClient) ListDHCPLeases(ctx context.Context) ([]dhcpd.Lease, error) {
	u := c.BaseURL + "/internal/dhcp/leases"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("engine dhcp leases status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		Leases []dhcpd.Lease `json:"leases"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Leases, nil
}

func (c *HTTPClient) DeleteConntrack(ctx context.Context, req conntrack.DeleteRequest) error {
	u := c.BaseURL + "/internal/conntrack"
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("engine conntrack delete status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// ListFlows fetches recent flow summaries derived from events.
func (c *HTTPClient) ListFlows(ctx context.Context, limit int) ([]dpevents.FlowSummary, error) {
	u := c.BaseURL + "/internal/flows"
	if limit > 0 {
		u += "?limit=" + url.QueryEscape(fmt.Sprintf("%d", limit))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("engine flows status %d", resp.StatusCode)
	}
	var out []dpevents.FlowSummary
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out == nil {
		return []dpevents.FlowSummary{}, nil
	}
	return out, nil
}

// SimulationStatus holds the state of the synthetic traffic generator.
type SimulationStatus struct {
	Running bool `json:"running"`
}

// SimulationStatus returns whether the synthetic traffic generator is running.
func (c *HTTPClient) SimulationStatus(ctx context.Context) (SimulationStatus, error) {
	if c.BaseURL == "" {
		return SimulationStatus{}, fmt.Errorf("engine BaseURL is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/internal/simulation", nil)
	if err != nil {
		return SimulationStatus{}, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return SimulationStatus{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		detail := strings.TrimSpace(string(b))
		if detail != "" {
			return SimulationStatus{}, fmt.Errorf("engine simulation status %d: %s", resp.StatusCode, detail)
		}
		return SimulationStatus{}, fmt.Errorf("engine simulation status %d", resp.StatusCode)
	}
	var st SimulationStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return SimulationStatus{}, err
	}
	return st, nil
}

// SimulationControl sends a start or stop action to the synthetic traffic generator.
func (c *HTTPClient) SimulationControl(ctx context.Context, action string) (SimulationStatus, error) {
	if c.BaseURL == "" {
		return SimulationStatus{}, fmt.Errorf("engine BaseURL is empty")
	}
	body, _ := json.Marshal(map[string]string{"action": action})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/simulation", bytes.NewReader(body))
	if err != nil {
		return SimulationStatus{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return SimulationStatus{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		detail := strings.TrimSpace(string(b))
		if detail != "" {
			return SimulationStatus{}, fmt.Errorf("engine simulation control %d: %s", resp.StatusCode, detail)
		}
		return SimulationStatus{}, fmt.Errorf("engine simulation control %d", resp.StatusCode)
	}
	var st SimulationStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return SimulationStatus{}, err
	}
	return st, nil
}

// AnalyzePcap uploads a PCAP file and runs offline DPI analysis on it.
func (c *HTTPClient) AnalyzePcap(ctx context.Context, filename string, r io.Reader) (*pcap.AnalysisResult, error) {
	if c.BaseURL == "" {
		return nil, fmt.Errorf("engine BaseURL is empty")
	}
	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)
	go func() {
		part, err := writer.CreateFormFile("file", filename)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if _, err := io.Copy(part, r); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if err := writer.Close(); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_ = pw.Close()
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/pcap/analyze", pr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("engine pcap analyze status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out pcap.AnalysisResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AnalyzePcapByName runs offline DPI analysis on an already-uploaded PCAP file.
func (c *HTTPClient) AnalyzePcapByName(ctx context.Context, name string) (*pcap.AnalysisResult, error) {
	if c.BaseURL == "" {
		return nil, fmt.Errorf("engine BaseURL is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/pcap/analyze/"+url.PathEscape(name), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("engine pcap analyze status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out pcap.AnalysisResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RulesetStatus fetches the last compiled/applied nftables ruleset status from the engine.
func (c *HTTPClient) RulesetStatus(ctx context.Context) (dpengine.RulesetStatus, error) {
	var out dpengine.RulesetStatus
	if c.BaseURL == "" {
		return out, fmt.Errorf("engine BaseURL is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/internal/ruleset_status", nil)
	if err != nil {
		return out, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return out, fmt.Errorf("engine ruleset_status status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}
