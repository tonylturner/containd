// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	engineclient "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
	"github.com/tonylturner/containd/pkg/dp/pcap"
	"github.com/tonylturner/containd/pkg/dp/stats"
)

type runtimeMockEngine struct {
	*mockEngine

	pcapCfgSet       config.PCAPConfig
	pcapStartCfg     config.PCAPConfig
	pcapStatusResp   pcap.Status
	pcapItemsResp    []pcap.Item
	pcapUploadResp   pcap.Item
	pcapDownloadResp *http.Response
	pcapDeleted      string
	pcapReplayReq    pcap.ReplayRequest

	eventsResp          []dpevents.Event
	eventsErr           error
	flowsResp           []dpevents.FlowSummary
	flowsErr            error
	simResp             engineclient.SimulationStatus
	simErr              error
	simAction           string
	protoStatsResp      []stats.ProtoStats
	protoStatsErr       error
	topTalkersResp      []stats.FlowStats
	topTalkersErr       error
	anomaliesResp       []anomaly.Anomaly
	anomaliesErr        error
	anomaliesCleared    bool
	conntrackResp       []conntrack.Entry
	conntrackErr        error
	conntrackDeleteReq  conntrack.DeleteRequest
	wireGuardStatusResp netcfg.WireGuardStatus
}

func newRuntimeMockEngine() *runtimeMockEngine {
	return &runtimeMockEngine{mockEngine: &mockEngine{}}
}

func (m *runtimeMockEngine) SetPcapConfig(ctx context.Context, cfg config.PCAPConfig) (config.PCAPConfig, error) {
	m.pcapCfgSet = cfg
	return cfg, nil
}

func (m *runtimeMockEngine) StartPcap(ctx context.Context, cfg config.PCAPConfig) (pcap.Status, error) {
	m.pcapStartCfg = cfg
	if len(m.pcapStatusResp.Interfaces) == 0 {
		m.pcapStatusResp.Interfaces = cfg.Interfaces
	}
	return m.pcapStatusResp, nil
}

func (m *runtimeMockEngine) PcapStatus(ctx context.Context) (pcap.Status, error) {
	return m.pcapStatusResp, nil
}

func (m *runtimeMockEngine) ListPcaps(ctx context.Context) ([]pcap.Item, error) {
	return m.pcapItemsResp, nil
}

func (m *runtimeMockEngine) UploadPcap(ctx context.Context, filename string, r io.Reader) (pcap.Item, error) {
	if m.pcapUploadResp.Name == "" {
		m.pcapUploadResp = pcap.Item{Name: filename, Interface: "wan"}
	}
	return m.pcapUploadResp, nil
}

func (m *runtimeMockEngine) DownloadPcap(ctx context.Context, name string) (*http.Response, error) {
	if m.pcapDownloadResp != nil {
		return m.pcapDownloadResp, nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(buildTestPCAP([][]byte{buildTestModbusEthernetFrame()}))),
		Header:     http.Header{"Content-Type": []string{"application/vnd.tcpdump.pcap"}},
	}, nil
}

func (m *runtimeMockEngine) DeletePcap(ctx context.Context, name string) error {
	m.pcapDeleted = name
	return nil
}

func (m *runtimeMockEngine) ReplayPcap(ctx context.Context, req pcap.ReplayRequest) error {
	m.pcapReplayReq = req
	return nil
}

func (m *runtimeMockEngine) ListEvents(ctx context.Context, limit int) ([]dpevents.Event, error) {
	return m.eventsResp, m.eventsErr
}

func (m *runtimeMockEngine) ListFlows(ctx context.Context, limit int) ([]dpevents.FlowSummary, error) {
	return m.flowsResp, m.flowsErr
}

func (m *runtimeMockEngine) SimulationStatus(ctx context.Context) (engineclient.SimulationStatus, error) {
	return m.simResp, m.simErr
}

func (m *runtimeMockEngine) SimulationControl(ctx context.Context, action string) (engineclient.SimulationStatus, error) {
	m.simAction = action
	if m.simErr != nil {
		return engineclient.SimulationStatus{}, m.simErr
	}
	m.simResp.Running = action == "start"
	return m.simResp, nil
}

func (m *runtimeMockEngine) ListProtoStats(ctx context.Context) ([]stats.ProtoStats, error) {
	return m.protoStatsResp, m.protoStatsErr
}

func (m *runtimeMockEngine) ListTopTalkers(ctx context.Context, n int) ([]stats.FlowStats, error) {
	return m.topTalkersResp, m.topTalkersErr
}

func (m *runtimeMockEngine) ListAnomalies(ctx context.Context, limit int) ([]anomaly.Anomaly, error) {
	return m.anomaliesResp, m.anomaliesErr
}

func (m *runtimeMockEngine) ClearAnomalies(ctx context.Context) error {
	m.anomaliesCleared = true
	return nil
}

func (m *runtimeMockEngine) ListConntrack(ctx context.Context, limit int) ([]conntrack.Entry, error) {
	return m.conntrackResp, m.conntrackErr
}

func (m *runtimeMockEngine) DeleteConntrack(ctx context.Context, req conntrack.DeleteRequest) error {
	m.conntrackDeleteReq = req
	return nil
}

func (m *runtimeMockEngine) GetWireGuardStatus(ctx context.Context, iface string) (netcfg.WireGuardStatus, error) {
	st := m.wireGuardStatusResp
	if strings.TrimSpace(st.Interface) == "" {
		st.Interface = iface
	}
	return st, nil
}

type telemetryOnlyServices struct {
	events []dpevents.Event
}

func (t telemetryOnlyServices) Apply(ctx context.Context, cfg config.ServicesConfig) error {
	return nil
}

func (t telemetryOnlyServices) ListTelemetryEvents(limit int) []dpevents.Event {
	if limit > 0 && len(t.events) > limit {
		return append([]dpevents.Event(nil), t.events[:limit]...)
	}
	return append([]dpevents.Event(nil), t.events...)
}

func buildTestPCAP(frames [][]byte) []byte {
	var buf bytes.Buffer
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(header[4:], 2)
	binary.LittleEndian.PutUint16(header[6:], 4)
	binary.LittleEndian.PutUint32(header[16:], 65535)
	binary.LittleEndian.PutUint32(header[20:], 1)
	buf.Write(header)

	baseTS := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	for i, frame := range frames {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:], uint32(baseTS.Unix())+uint32(i))
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(frame)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(frame)))
		buf.Write(rec)
		buf.Write(frame)
	}
	return buf.Bytes()
}

func buildTestModbusEthernetFrame() []byte {
	mbap := make([]byte, 12)
	binary.BigEndian.PutUint16(mbap[0:], 1)
	binary.BigEndian.PutUint16(mbap[4:], 6)
	mbap[6] = 1
	mbap[7] = 3
	binary.BigEndian.PutUint16(mbap[10:], 10)

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 49152)
	binary.BigEndian.PutUint16(tcp[2:], 502)
	tcp[12] = 5 << 4

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+20+len(mbap)))
	ip[9] = 6
	ip[12], ip[13], ip[14], ip[15] = 10, 0, 0, 1
	ip[16], ip[17], ip[18], ip[19] = 10, 0, 0, 2

	eth := make([]byte, 14)
	eth[5] = 2
	eth[11] = 1
	binary.BigEndian.PutUint16(eth[12:], 0x0800)

	var frame []byte
	frame = append(frame, eth...)
	frame = append(frame, ip...)
	frame = append(frame, tcp...)
	frame = append(frame, mbap...)
	return frame
}

func multipartAuthedRequest(t *testing.T, method, path, fieldName, filename string, content []byte) *http.Request {
	t.Helper()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile(fieldName, filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("Write content: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close writer: %v", err)
	}

	req, _ := http.NewRequest(method, path, &body)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func TestPCAPRuntimeHandlers(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.PCAP.Interfaces = []string{"wan"}
	store := &mockStore{cfg: cfg}
	eng := newRuntimeMockEngine()
	eng.pcapStatusResp = pcap.Status{Running: true, Interfaces: []string{"wan"}}
	eng.pcapItemsResp = []pcap.Item{{Name: "sample.pcap", Interface: "wan"}}
	eng.pcapUploadResp = pcap.Item{Name: "upload.pcap", Interface: "wan"}
	eng.pcapDownloadResp = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("pcap-download")),
		Header: http.Header{
			"Content-Type":        []string{"application/vnd.tcpdump.pcap"},
			"Content-Disposition": []string{`attachment; filename="sample.pcap"`},
		},
	}

	s := NewServerWithEngine(store, nil, eng)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/pcap/config", bytes.NewBufferString(`{"interfaces":["wan"],"mode":"once","snaplen":256}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("pcap config: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if got := strings.Join(eng.pcapCfgSet.Interfaces, ","); got != "wan" {
		t.Fatalf("pcap config interfaces = %q", got)
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodPost, "/api/v1/pcap/start", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("pcap start: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !store.cfg.PCAP.Enabled {
		t.Fatal("expected pcap to be enabled in saved config")
	}
	if got := strings.Join(eng.pcapStartCfg.Interfaces, ","); got != "wan" {
		t.Fatalf("pcap start interfaces = %q", got)
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/pcap/status", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"running":true`) {
		t.Fatalf("pcap status: expected running response, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/pcap/list", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "sample.pcap") {
		t.Fatalf("pcap list: expected item response, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = multipartAuthedRequest(t, http.MethodPost, "/api/v1/pcap/upload", "file", "upload.pcap", buildTestPCAP([][]byte{buildTestModbusEthernetFrame()}))
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "upload.pcap") {
		t.Fatalf("pcap upload: expected 200 upload response, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/pcap/download/sample.pcap", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "pcap-download" {
		t.Fatalf("pcap download: expected download body, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodPost, "/api/v1/pcap/replay", bytes.NewBufferString(`{"name":"sample.pcap","interface":"wan","ratePps":100}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("pcap replay: expected 202, got %d body=%s", rec.Code, rec.Body.String())
	}
	if eng.pcapReplayReq.Name != "sample.pcap" || eng.pcapReplayReq.Interface != "wan" {
		t.Fatalf("unexpected replay request %+v", eng.pcapReplayReq)
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodDelete, "/api/v1/pcap/sample.pcap", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("pcap delete: expected 204, got %d body=%s", rec.Code, rec.Body.String())
	}
	if eng.pcapDeleted != "sample.pcap" {
		t.Fatalf("pcap delete target = %q", eng.pcapDeleted)
	}

	rec = httptest.NewRecorder()
	req = multipartAuthedRequest(t, http.MethodPost, "/api/v1/pcap/analyze", "file", "sample.pcap", buildTestPCAP([][]byte{buildTestModbusEthernetFrame()}))
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("pcap analyze upload: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var uploadAnalysis pcap.PolicyAnalysis
	if err := json.Unmarshal(rec.Body.Bytes(), &uploadAnalysis); err != nil {
		t.Fatalf("decode upload analysis: %v", err)
	}
	if uploadAnalysis.Stats.PacketCount != 1 {
		t.Fatalf("upload analysis packetCount = %d", uploadAnalysis.Stats.PacketCount)
	}

	eng.pcapDownloadResp = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(buildTestPCAP([][]byte{buildTestModbusEthernetFrame()}))),
		Header:     http.Header{"Content-Type": []string{"application/vnd.tcpdump.pcap"}},
	}
	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodPost, "/api/v1/pcap/analyze/sample.pcap", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("pcap analyze by name: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var namedAnalysis pcap.PolicyAnalysis
	if err := json.Unmarshal(rec.Body.Bytes(), &namedAnalysis); err != nil {
		t.Fatalf("decode named analysis: %v", err)
	}
	if namedAnalysis.Stats.PacketCount != 1 {
		t.Fatalf("named analysis packetCount = %d", namedAnalysis.Stats.PacketCount)
	}
}

func TestRuntimeTelemetryHandlers(t *testing.T) {
	eng := newRuntimeMockEngine()
	eng.eventsResp = []dpevents.Event{{
		ID:        7,
		Proto:     "modbus",
		Kind:      "request",
		Timestamp: time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
	}}
	eng.flowsResp = []dpevents.FlowSummary{{FlowID: "flow-1", Application: "modbus", EventCount: 2}}
	eng.simResp = engineclient.SimulationStatus{Running: false}
	eng.protoStatsResp = []stats.ProtoStats{{Protocol: "modbus", PacketCount: 4}}
	eng.topTalkersResp = []stats.FlowStats{{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: "tcp", Packets: 4}}
	eng.anomaliesResp = []anomaly.Anomaly{{Type: "malformed_frame", Protocol: "modbus", Severity: "high"}}
	eng.conntrackResp = []conntrack.Entry{{Proto: "tcp", Src: "10.0.0.1", Dst: "10.0.0.2", Dport: "502"}}

	s := NewServerWithEngine(&mockStore{}, nil, eng)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/events?limit=10", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"id":7`) {
		t.Fatalf("events list: expected event payload, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/events/7", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"modbus"`) {
		t.Fatalf("event detail: expected event payload, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/flows?limit=5", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "flow-1") {
		t.Fatalf("flows: expected flow payload, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/simulation", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"running":false`) {
		t.Fatalf("simulation status: expected status payload, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodPost, "/api/v1/simulation", bytes.NewBufferString(`{"action":"start"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"running":true`) {
		t.Fatalf("simulation control: expected running payload, got %d body=%s", rec.Code, rec.Body.String())
	}
	if eng.simAction != "start" {
		t.Fatalf("simulation action = %q", eng.simAction)
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/stats/protocols", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"protocol":"modbus"`) {
		t.Fatalf("protocol stats: expected stats payload, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/stats/top-talkers?n=5", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"srcIp":"10.0.0.1"`) {
		t.Fatalf("top talkers: expected payload, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/anomalies?limit=5", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"malformed_frame"`) {
		t.Fatalf("anomalies: expected payload, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodDelete, "/api/v1/anomalies", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !eng.anomaliesCleared {
		t.Fatalf("clear anomalies: expected 200 and clear call, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/conntrack?limit=5", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"dport":"502"`) {
		t.Fatalf("conntrack list: expected payload, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodPost, "/api/v1/conntrack/kill", bytes.NewBufferString(`{"proto":"tcp","src":"10.0.0.1","dst":"10.0.0.2","sport":1111,"dport":502}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || eng.conntrackDeleteReq.Dport != 502 {
		t.Fatalf("conntrack kill: expected delete call, got %d body=%s req=%+v", rec.Code, rec.Body.String(), eng.conntrackDeleteReq)
	}
}

func TestRuntimeTelemetryFallbackAndUnavailablePaths(t *testing.T) {
	store := &mockStore{}
	eng := newRuntimeMockEngine()
	eng.eventsErr = errors.New("telemetry offline")

	services := telemetryOnlyServices{events: []dpevents.Event{{
		ID:        21,
		Proto:     "service",
		Kind:      "service.syslog.forwarded",
		Timestamp: time.Date(2026, 3, 13, 10, 0, 0, 0, time.UTC),
	}}}

	s := NewServerWithEngineAndServices(store, nil, eng, services, nil)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/events", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `service.syslog.forwarded`) || !strings.Contains(rec.Body.String(), `system.engine.telemetry_error`) {
		t.Fatalf("events fallback: expected merged service event and telemetry error, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/events/not-a-number", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("event detail invalid id: expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/events/999", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("event detail not found: expected 404, got %d body=%s", rec.Code, rec.Body.String())
	}

	noEngine := NewServer(&mockStore{}, nil)

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/flows", nil)
	noEngine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("flows without engine: expected empty array, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/stats/protocols", nil)
	noEngine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("proto stats without engine: expected empty array, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/stats/top-talkers", nil)
	noEngine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("top talkers without engine: expected empty array, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/anomalies", nil)
	noEngine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("anomalies without engine: expected empty array, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodPost, "/api/v1/simulation", bytes.NewBufferString(`{"action":"start"}`))
	req.Header.Set("Content-Type", "application/json")
	noEngine.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "simulation unavailable") {
		t.Fatalf("simulation without engine: expected unavailable error, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRuntimeTelemetryGatewayErrorsAndStoreLoadFailures(t *testing.T) {
	eng := newRuntimeMockEngine()
	eng.flowsErr = errors.New("flows failed")
	eng.topTalkersErr = errors.New("talkers failed")
	eng.anomaliesErr = errors.New("anomalies failed")
	eng.conntrackErr = errors.New("conntrack failed")

	s := NewServerWithEngine(&mockStore{}, nil, eng)

	for _, tc := range []struct {
		path string
		name string
	}{
		{path: "/api/v1/flows", name: "flows"},
		{path: "/api/v1/stats/top-talkers", name: "top-talkers"},
		{path: "/api/v1/anomalies", name: "anomalies"},
		{path: "/api/v1/conntrack", name: "conntrack"},
	} {
		rec := httptest.NewRecorder()
		req := authedRequest(http.MethodGet, tc.path, nil)
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("%s gateway error: expected 502, got %d body=%s", tc.name, rec.Code, rec.Body.String())
		}
	}

	errStore := &mockStore{load: func() (*config.Config, error) {
		return nil, errors.New("boom")
	}}
	s = NewServer(errStore, nil)

	for _, tc := range []struct {
		path string
		name string
	}{
		{path: "/api/v1/interfaces", name: "interfaces"},
		{path: "/api/v1/services/syslog", name: "syslog"},
		{path: "/api/v1/services/dns", name: "dns"},
		{path: "/api/v1/services/ntp", name: "ntp"},
	} {
		rec := httptest.NewRecorder()
		req := authedRequest(http.MethodGet, tc.path, nil)
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("%s load error: expected 500, got %d body=%s", tc.name, rec.Code, rec.Body.String())
		}
	}
}

func TestVPNServiceHelperHandlers(t *testing.T) {
	t.Setenv("CONTAIND_OPENVPN_DIR", t.TempDir())

	cfg := config.DefaultConfig()
	cfg.Services.VPN.OpenVPN.Enabled = true
	cfg.Services.VPN.OpenVPN.Mode = "server"
	cfg.Services.VPN.OpenVPN.Server = &config.OpenVPNManagedServerConfig{
		ListenZone:     "wan",
		TunnelCIDR:     "10.9.0.0/24",
		PublicEndpoint: "vpn.example.com",
	}
	store := &mockStore{cfg: cfg}
	eng := newRuntimeMockEngine()
	eng.wireGuardStatusResp = netcfg.WireGuardStatus{
		Interface:  "wg0",
		Present:    true,
		ListenPort: 51820,
	}

	s := NewServerWithEngine(store, nil, eng)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/services/vpn/openvpn/profile", bytes.NewBufferString(`{"name":"labclient","ovpn":"client\nremote 198.51.100.10 1194\nproto udp\n"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload openvpn profile: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if got := filepath.Base(store.cfg.Services.VPN.OpenVPN.ConfigPath); got != "labclient.ovpn" {
		t.Fatalf("unexpected config path %q", store.cfg.Services.VPN.OpenVPN.ConfigPath)
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodPost, "/api/v1/services/vpn/openvpn/clients", bytes.NewBufferString(`{"name":"labuser01"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "labuser01") {
		t.Fatalf("create openvpn client: expected client payload, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/services/vpn/openvpn/clients", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "labuser01") {
		t.Fatalf("list openvpn clients: expected created client, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/services/vpn/openvpn/clients/labuser01", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<ca>") || !strings.Contains(rec.Body.String(), "remote vpn.example.com 1194") {
		t.Fatalf("download openvpn client: expected inline profile, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/services/vpn/wireguard/status?iface=wg0", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"listenPort":51820`) {
		t.Fatalf("wireguard status: expected payload, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestVPNServiceReadWritePreservesRedactedSecrets(t *testing.T) {
	wireGuardKey := testSensitiveValue("wireguard-runtime")
	managedPassword := testSensitiveValue("managed-openvpn")
	cfg := config.DefaultConfig()
	cfg.Services.VPN.WireGuard = config.WireGuardConfig{
		Enabled:    true,
		Interface:  "wg0",
		PrivateKey: wireGuardKey,
	}
	cfg.Services.VPN.OpenVPN.Managed = &config.OpenVPNManagedClientConfig{
		Remote:   "vpn.example.com",
		Port:     1194,
		Proto:    "udp",
		Username: "vpn-user",
		Password: managedPassword,
		CA:       "ca-bytes",
		Cert:     "cert-bytes",
		Key:      "key-bytes",
	}

	store := &mockStore{cfg: cfg}
	eng := &mockEngine{svcErr: errors.New("runtime services unavailable")}
	s := NewServerWithEngine(store, nil, eng)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/services/vpn", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get vpn: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var redacted config.VPNConfig
	if err := json.Unmarshal(rec.Body.Bytes(), &redacted); err != nil {
		t.Fatalf("decode vpn: %v", err)
	}
	if redacted.WireGuard.PrivateKey != "" {
		t.Fatalf("expected wireguard private key redacted, got %q", redacted.WireGuard.PrivateKey)
	}
	if redacted.OpenVPN.Managed == nil {
		t.Fatal("expected managed openvpn config")
	}
	if redacted.OpenVPN.Managed.Password != "" || redacted.OpenVPN.Managed.CA != "" || redacted.OpenVPN.Managed.Cert != "" || redacted.OpenVPN.Managed.Key != "" {
		t.Fatalf("expected openvpn managed secrets redacted, got %#v", redacted.OpenVPN.Managed)
	}

	redacted.OpenVPN.Managed.Remote = "vpn2.example.com"
	body, err := json.Marshal(redacted)
	if err != nil {
		t.Fatalf("marshal vpn update: %v", err)
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodPost, "/api/v1/services/vpn", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("set vpn: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Containd-Warnings"); !strings.Contains(got, "engine services: runtime services unavailable") {
		t.Fatalf("expected runtime warning header, got %q", got)
	}

	if store.cfg.Services.VPN.WireGuard.PrivateKey != wireGuardKey {
		t.Fatalf("wireguard secret lost after redacted round trip: %#v", store.cfg.Services.VPN.WireGuard)
	}
	if store.cfg.Services.VPN.OpenVPN.Managed == nil {
		t.Fatal("expected managed openvpn config to persist")
	}
	if store.cfg.Services.VPN.OpenVPN.Managed.Password != managedPassword ||
		store.cfg.Services.VPN.OpenVPN.Managed.CA != "ca-bytes" ||
		store.cfg.Services.VPN.OpenVPN.Managed.Cert != "cert-bytes" ||
		store.cfg.Services.VPN.OpenVPN.Managed.Key != "key-bytes" {
		t.Fatalf("managed openvpn secrets lost after redacted round trip: %#v", store.cfg.Services.VPN.OpenVPN.Managed)
	}
	if store.cfg.Services.VPN.OpenVPN.Managed.Remote != "vpn2.example.com" {
		t.Fatalf("expected updated managed remote, got %#v", store.cfg.Services.VPN.OpenVPN.Managed)
	}
}
