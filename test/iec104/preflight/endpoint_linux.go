//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type endpointConn struct {
	mu         sync.Mutex
	id         int
	conn       net.Conn
	received   []byte
	readError  string
	writeError string
	done       bool
	localAddr  string
	remoteAddr string
}

type connSnapshot struct {
	ID         int    `json:"id"`
	Received   string `json:"received"`
	ReadError  string `json:"read_error"`
	WriteError string `json:"write_error"`
	Done       bool   `json:"done"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
}

type endpointService struct {
	mode       string
	serverAddr string
	mu         sync.RWMutex
	conns      map[int]*endpointConn
	nextID     int
}

type writeRequest struct {
	Data      string `json:"data"`
	ChunkSize int    `json:"chunk_size"`
	GapMS     int    `json:"gap_ms"`
}

func runEndpoint(mode string) error {
	service := &endpointService{
		mode:       mode,
		serverAddr: serverAddress(),
		conns:      make(map[int]*endpointConn),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mode": mode})
	})
	mux.HandleFunc("/connect", service.handleConnect)
	mux.HandleFunc("/send", service.handleSend)
	mux.HandleFunc("/write", service.handleSend)
	mux.HandleFunc("/close", service.handleClose)
	mux.HandleFunc("/conn", service.handleConn)
	mux.HandleFunc("/connections", service.handleConnections)
	if mode == "server" {
		listener, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", strconv.Itoa(serverPort)))
		if err != nil {
			return fmt.Errorf("listen TCP %d: %w", serverPort, err)
		}
		go service.accept(listener)
	}
	return controlHandler("127.0.0.1:8080", mux)
}

func serverAddress() string {
	return net.JoinHostPort(serverIP, strconv.Itoa(serverPort))
}

func (s *endpointService) accept(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
		}
		s.addConn(conn)
	}
}

func (s *endpointService) addConn(conn net.Conn) *endpointConn {
	s.mu.Lock()
	s.nextID++
	entry := &endpointConn{
		id:         s.nextID,
		conn:       conn,
		localAddr:  conn.LocalAddr().String(),
		remoteAddr: conn.RemoteAddr().String(),
	}
	s.conns[entry.id] = entry
	s.mu.Unlock()
	go entry.readLoop()
	return entry
}

func (c *endpointConn) readLoop() {
	buf := make([]byte, 16*1024)
	for {
		n, err := c.conn.Read(buf)
		c.mu.Lock()
		if n > 0 {
			c.received = append(c.received, buf[:n]...)
		}
		if err != nil {
			c.done = true
			if !errors.Is(err, io.EOF) {
				c.readError = err.Error()
			} else {
				c.readError = "EOF"
			}
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()
	}
}

func (c *endpointConn) snapshot() connSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return connSnapshot{
		ID:         c.id,
		Received:   string(c.received),
		ReadError:  c.readError,
		WriteError: c.writeError,
		Done:       c.done,
		LocalAddr:  c.localAddr,
		RemoteAddr: c.remoteAddr,
	}
}

func (s *endpointService) conn(id int) (*endpointConn, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.conns[id]
	return entry, ok
}

func (s *endpointService) handleConnect(w http.ResponseWriter, r *http.Request) {
	if s.mode != "client" || r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("POST /connect is available only on the client"))
		return
	}
	conn, err := net.DialTimeout("tcp", s.serverAddr, 3*time.Second)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Errorf("dial server: %w", err))
		return
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	entry := s.addConn(conn)
	writeJSON(w, http.StatusCreated, entry.snapshot())
}

func (s *endpointService) handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("POST required"))
		return
	}
	id, err := parseID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	entry, ok := s.conn(id)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("connection %d not found", id))
		return
	}
	var req writeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.ChunkSize < 0 || req.GapMS < 0 || req.GapMS > 1000 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid chunk size or gap"))
		return
	}
	payload := []byte(req.Data)
	chunkSize := req.ChunkSize
	if chunkSize == 0 || chunkSize > len(payload) {
		chunkSize = len(payload)
	}
	for offset := 0; offset < len(payload); {
		end := offset + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		if err := writeAll(entry.conn, payload[offset:end]); err != nil {
			entry.mu.Lock()
			entry.writeError = err.Error()
			entry.mu.Unlock()
			writeError(w, http.StatusBadGateway, fmt.Errorf("write connection %d: %w", id, err))
			return
		}
		offset = end
		if offset < len(payload) && req.GapMS > 0 {
			time.Sleep(time.Duration(req.GapMS) * time.Millisecond)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "bytes_written": len(payload)})
}

func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func (s *endpointService) handleConn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("GET required"))
		return
	}
	id, err := parseID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	entry, ok := s.conn(id)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("connection %d not found", id))
		return
	}
	writeJSON(w, http.StatusOK, entry.snapshot())
}

func (s *endpointService) handleClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("POST required"))
		return
	}
	id, err := parseID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	entry, ok := s.conn(id)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("connection %d not found", id))
		return
	}
	err = entry.conn.Close()
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "closed": true})
}

func (s *endpointService) handleConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("GET required"))
		return
	}
	s.mu.RLock()
	entries := make([]*endpointConn, 0, len(s.conns))
	for _, entry := range s.conns {
		entries = append(entries, entry)
	}
	s.mu.RUnlock()
	snapshots := make([]connSnapshot, 0, len(entries))
	for _, entry := range entries {
		snapshots = append(snapshots, entry.snapshot())
	}
	writeJSON(w, http.StatusOK, snapshots)
}
