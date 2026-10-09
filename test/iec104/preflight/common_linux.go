//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	clientIP    = "10.250.0.10"
	serverIP    = "10.251.0.10"
	serverPort  = 2404
	queueNumber = 101
)

type packet struct {
	ID         uint32    `json:"id"`
	ObservedAt time.Time `json:"observed_at"`
	SrcIP      string    `json:"src_ip"`
	DstIP      string    `json:"dst_ip"`
	SrcPort    uint16    `json:"src_port"`
	DstPort    uint16    `json:"dst_port"`
	Seq        uint32    `json:"seq"`
	Ack        uint32    `json:"ack"`
	Flags      uint8     `json:"flags"`
	PayloadLen int       `json:"payload_len"`
	PacketLen  int       `json:"packet_len"`
	Prefix     string    `json:"prefix"`
	Direction  string    `json:"direction"`
	Matched    bool      `json:"matched"`
	Held       bool      `json:"held"`
	Verdict    string    `json:"verdict,omitempty"`
	VerdictErr string    `json:"verdict_error,omitempty"`
	VerdictMS  float64   `json:"setverdict_ms,omitempty"`
	HeldAt     time.Time `json:"held_at,omitempty"`
	ResolvedAt time.Time `json:"resolved_at,omitempty"`
	HoldMS     float64   `json:"hold_ms,omitempty"`
}

type rule struct {
	Prefix    string `json:"prefix"`
	Direction string `json:"direction"`
	Action    string `json:"action"`
	DelayMS   int    `json:"delay_ms"`
}

type verdictRequest struct {
	ID     uint32 `json:"id"`
	Action string `json:"action"`
}

type rstRequest struct {
	Target     string `json:"target"`
	ClientPort uint16 `json:"client_port"`
	Seq        uint32 `json:"seq"`
}

type sequenceState struct {
	ClientPort     uint16    `json:"client_port"`
	ExpectedClient uint32    `json:"expected_client"`
	ExpectedServer uint32    `json:"expected_server"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func parsePacket(id uint32, raw []byte) (packet, []byte, bool) {
	var p packet
	if len(raw) < 20 || raw[0]>>4 != 4 {
		return p, nil, false
	}
	ipHeaderLen := int(raw[0]&0x0f) * 4
	if ipHeaderLen < 20 || len(raw) < ipHeaderLen+20 || raw[9] != 6 {
		return p, nil, false
	}
	if binary.BigEndian.Uint16(raw[6:8])&0x1fff != 0 {
		return p, nil, false
	}
	tcp := raw[ipHeaderLen:]
	tcpHeaderLen := int(tcp[12]>>4) * 4
	if tcpHeaderLen < 20 || len(tcp) < tcpHeaderLen {
		return p, nil, false
	}
	src, ok1 := netip.AddrFromSlice(raw[12:16])
	dst, ok2 := netip.AddrFromSlice(raw[16:20])
	if !ok1 || !ok2 {
		return p, nil, false
	}
	payload := tcp[tcpHeaderLen:]
	p = packet{
		ID:         id,
		ObservedAt: time.Now(),
		SrcIP:      src.String(),
		DstIP:      dst.String(),
		SrcPort:    binary.BigEndian.Uint16(tcp[0:2]),
		DstPort:    binary.BigEndian.Uint16(tcp[2:4]),
		Seq:        binary.BigEndian.Uint32(tcp[4:8]),
		Ack:        binary.BigEndian.Uint32(tcp[8:12]),
		Flags:      tcp[13],
		PayloadLen: len(payload),
		PacketLen:  len(raw),
	}
	if p.SrcIP == clientIP {
		p.Direction = "c2s"
	} else if p.SrcIP == serverIP {
		p.Direction = "s2c"
	} else {
		p.Direction = "other"
	}
	prefixLen := len(payload)
	if prefixLen > 160 {
		prefixLen = 160
	}
	p.Prefix = string(bytes.ToValidUTF8(payload[:prefixLen], []byte("?")))
	return p, payload, true
}

func controlHandler(addr string, handler http.Handler) error {
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 3 * time.Second,
	}
	return server.ListenAndServe()
}

func decodeJSON(r *http.Request, target any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		return
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func parseID(r *http.Request) (int, error) {
	id, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil || id < 1 {
		return 0, fmt.Errorf("query id must be a positive integer")
	}
	return id, nil
}

func requestJSON(method, url string, body any) (json.RawMessage, int, error) {
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, payload)
	}
	return payload, resp.StatusCode, nil
}

func runControlCLI(args []string) error {
	if len(args) < 3 || len(args) > 4 {
		return fmt.Errorf("usage: preflight ctl BASE_URL METHOD PATH [JSON_BODY]")
	}
	var body any
	if len(args) == 4 {
		if err := json.Unmarshal([]byte(args[3]), &body); err != nil {
			return fmt.Errorf("invalid JSON body: %w", err)
		}
	}
	raw, _, err := requestJSON(args[1], args[0]+args[2], body)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(raw)
	if err == nil {
		_, err = fmt.Fprintln(os.Stdout)
	}
	return err
}

type parallelVerdictResult struct {
	ID             uint32  `json:"id"`
	HTTPDurationMS float64 `json:"http_duration_ms"`
	Error          string  `json:"error,omitempty"`
}

// runParallelVerdicts submits one POST per packet concurrently. It deliberately
// does not retry failures: a timed-out request may still be executing remotely.
func runParallelVerdicts(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: preflight parallel-verdict BASE_URL PACKET_ID...")
	}
	baseURL := args[0]
	ids := make([]uint32, len(args)-1)
	for i, rawID := range args[1:] {
		id, err := strconv.ParseUint(rawID, 10, 32)
		if err != nil || id == 0 {
			return fmt.Errorf("packet id %q must be a positive uint32", rawID)
		}
		ids[i] = uint32(id)
	}

	results := make([]parallelVerdictResult, len(ids))
	var workers sync.WaitGroup
	for i, id := range ids {
		workers.Add(1)
		go func(i int, id uint32) {
			defer workers.Done()
			started := time.Now()
			body := map[string]any{"id": id, "action": "accept"}
			_, _, err := requestJSON(http.MethodPost, baseURL+"/verdict", body)
			results[i] = parallelVerdictResult{
				ID:             id,
				HTTPDurationMS: float64(time.Since(started)) / float64(time.Millisecond),
			}
			if err != nil {
				results[i].Error = err.Error()
			}
		}(i, id)
	}
	workers.Wait()

	if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
		return fmt.Errorf("write parallel verdict results: %w", err)
	}
	failed := 0
	for _, result := range results {
		if result.Error != "" {
			failed++
		}
	}
	if failed != 0 {
		return fmt.Errorf("%d of %d parallel verdict submissions failed (see JSON output)", failed, len(results))
	}
	return nil
}
