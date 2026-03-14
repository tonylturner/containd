// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/pcap"
)

func pcapConfigHandler(mgr *pcap.Manager, ownership *ownershipManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, mgr.Config())
			return
		case http.MethodPost:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}
			var cfg config.PCAPConfig
			if err := json.Unmarshal(body, &cfg); err != nil {
				http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
				return
			}
			if ownership != nil {
				cfg.Interfaces = resolveInterfaceRefs(cfg.Interfaces, ownership.currentInterfaces())
			}
			wasRunning := mgr.Status().Running
			if err := mgr.Configure(cfg); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if wasRunning {
				_ = mgr.Stop()
				if cfg.Enabled {
					if err := mgr.Start(r.Context(), cfg); err != nil {
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
				}
			}
			writeJSON(w, mgr.Config())
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}
}

func pcapStartHandler(mgr *pcap.Manager, ownership *ownershipManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cfg := mgr.Config()
		if r.ContentLength > 0 {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}
			if err := json.Unmarshal(body, &cfg); err != nil {
				http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		if ownership != nil {
			cfg.Interfaces = resolveInterfaceRefs(cfg.Interfaces, ownership.currentInterfaces())
		}
		if err := mgr.Start(r.Context(), cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, mgr.Status())
	}
}

func pcapStopHandler(mgr *pcap.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = mgr.Stop()
		writeJSON(w, mgr.Status())
	}
}

func pcapStatusHandler(mgr *pcap.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, mgr.Status())
	}
}

func pcapListHandler(mgr *pcap.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		items, err := mgr.List()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, items)
	}
}

func pcapUploadHandler(mgr *pcap.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseMultipartForm(64 << 20); err != nil {
			http.Error(w, "invalid multipart form: "+err.Error(), http.StatusBadRequest)
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "file required", http.StatusBadRequest)
			return
		}
		defer file.Close()
		// Validate PCAP/PCAPng magic bytes.
		var magic [4]byte
		if _, err := io.ReadFull(file, magic[:]); err != nil {
			http.Error(w, "file too small or unreadable", http.StatusBadRequest)
			return
		}
		switch {
		case magic == [4]byte{0xd4, 0xc3, 0xb2, 0xa1}: // pcap LE
		case magic == [4]byte{0xa1, 0xb2, 0xc3, 0xd4}: // pcap BE
		case magic == [4]byte{0x0a, 0x0d, 0x0d, 0x0a}: // pcapng
		default:
			http.Error(w, "not a valid pcap/pcapng file", http.StatusBadRequest)
			return
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			http.Error(w, "failed to rewind file", http.StatusInternalServerError)
			return
		}
		item, err := mgr.Upload(header.Filename, file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, item)
	}
}

func pcapDownloadHandler(mgr *pcap.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		f, size, err := mgr.Open(name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
		_, _ = io.Copy(w, f)
	}
}

func pcapTagHandler(mgr *pcap.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req pcap.TagRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		if err := mgr.Tag(req.Name, req.Tags); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func pcapDeleteHandler(mgr *pcap.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		if err := mgr.Delete(name); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func pcapReplayHandler(mgr *pcap.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req pcap.ReplayRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Name == "" || req.Interface == "" {
			http.Error(w, "name and interface required", http.StatusBadRequest)
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			if err := mgr.Replay(ctx, req); err != nil {
				slog.Error("pcap replay failed", "name", req.Name, "error", err)
			}
		}()
		w.WriteHeader(http.StatusAccepted)
	}
}

func pcapAnalyzeUploadHandler(mgr *pcap.Manager, dpEngine *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseMultipartForm(64 << 20); err != nil {
			http.Error(w, "invalid multipart form: "+err.Error(), http.StatusBadRequest)
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "file required", http.StatusBadRequest)
			return
		}
		defer file.Close()

		var decoders []dpi.Decoder
		if dpEngine != nil && dpEngine.DPI() != nil {
			decoders = dpEngine.DPI().Decoders()
		}
		result, err := pcap.Analyze(file, decoders...)
		if err != nil {
			http.Error(w, "analysis failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, result)
	}
}

func pcapAnalyzeNameHandler(mgr *pcap.Manager, dpEngine *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Extract name from path: /internal/pcap/analyze/<name>
		name := strings.TrimPrefix(r.URL.Path, "/internal/pcap/analyze/")
		name = strings.TrimSpace(name)
		if name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		f, _, err := mgr.Open(name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()

		var decoders []dpi.Decoder
		if dpEngine != nil && dpEngine.DPI() != nil {
			decoders = dpEngine.DPI().Decoders()
		}
		result, err := pcap.Analyze(f, decoders...)
		if err != nil {
			http.Error(w, "analysis failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, result)
	}
}
