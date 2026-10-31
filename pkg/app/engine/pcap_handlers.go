// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/pcap"
	"github.com/tonylturner/containd/pkg/evidence"
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
			wasRunning := mgr.Status().Running
			if ownership != nil && wasRunning && cfg.Enabled {
				cfg, err = resolvePCAPConfig(cfg, ownership.currentInterfaces(), net.InterfaceByName)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
			}
			if err := mgr.Configure(cfg); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if wasRunning {
				_ = mgr.Stop()
				if cfg.Enabled {
					if err := mgr.Start(cfg); err != nil {
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
			resolved, err := resolvePCAPConfig(cfg, ownership.currentInterfaces(), net.InterfaceByName)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			cfg = resolved
		}
		if err := mgr.Start(cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, mgr.Status())
	}
}

func resolvePCAPConfig(cfg config.PCAPConfig, ifaces []config.Interface, lookup func(string) (*net.Interface, error)) (config.PCAPConfig, error) {
	if len(cfg.Interfaces) == 0 && len(cfg.Zones) == 0 {
		return config.PCAPConfig{}, fmt.Errorf("pcap requires at least one interface or zone")
	}

	logical := make(map[string]string, len(ifaces))
	kernelDevice := func(iface config.Interface) string {
		if device := strings.TrimSpace(iface.Device); device != "" {
			return device
		}
		return strings.TrimSpace(iface.Name)
	}
	for _, iface := range ifaces {
		name := strings.TrimSpace(iface.Name)
		if name == "" {
			continue
		}
		logical[name] = kernelDevice(iface)
	}

	resolved := make([]string, 0, len(cfg.Interfaces)+len(ifaces))
	seen := make(map[string]struct{}, cap(resolved))
	addDevice := func(device string) {
		if _, ok := seen[device]; !ok {
			seen[device] = struct{}{}
			resolved = append(resolved, device)
		}
	}
	resolveInterface := func(ref string) error {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return fmt.Errorf("pcap.interfaces cannot include empty name")
		}
		if device, ok := logical[ref]; ok {
			if _, err := lookup(device); err != nil {
				return fmt.Errorf("pcap interface %q has no existing kernel device %q: %w", ref, device, err)
			}
			addDevice(device)
			return nil
		}
		if _, err := lookup(ref); err == nil {
			addDevice(ref)
			return nil
		}
		return fmt.Errorf("pcap interface %q is not a configured logical interface or existing kernel device", ref)
	}

	for _, ref := range cfg.Interfaces {
		if err := resolveInterface(ref); err != nil {
			return config.PCAPConfig{}, err
		}
	}
	for _, zone := range cfg.Zones {
		zone = strings.TrimSpace(zone)
		if zone == "" {
			return config.PCAPConfig{}, fmt.Errorf("pcap.zones cannot include empty name")
		}
		found := false
		bound := false
		var unbound []string
		for _, iface := range ifaces {
			if strings.TrimSpace(iface.Zone) != zone {
				continue
			}
			found = true
			device := kernelDevice(iface)
			if device != "" {
				if _, err := lookup(device); err == nil {
					bound = true
					addDevice(device)
					continue
				}
			}
			unbound = append(unbound, fmt.Sprintf("%q", iface.Name))
		}
		if !found {
			return config.PCAPConfig{}, fmt.Errorf("pcap zone %q has no configured interfaces", zone)
		}
		if !bound {
			return config.PCAPConfig{}, fmt.Errorf("pcap zone %q has no kernel devices (%s unbound); bind members to existing devices", zone, strings.Join(unbound, ", "))
		}
	}
	if len(resolved) == 0 {
		return config.PCAPConfig{}, fmt.Errorf("pcap interface and zone selection resolves to no devices")
	}
	cfg.Interfaces = resolved
	cfg.Zones = nil
	return cfg, nil
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
		r.Body = http.MaxBytesReader(w, r.Body, 65<<20)
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			http.Error(w, "invalid multipart form: "+err.Error(), http.StatusBadRequest)
			return
		}
		if r.MultipartForm != nil {
			defer func() {
				if err := r.MultipartForm.RemoveAll(); err != nil {
					slog.Warn("multipart cleanup failed", "error", err)
				}
			}()
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

func pcapAnalyzeUploadHandler(mgr *pcap.Manager, dpEngine *engine.Engine, store evidence.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if dpEngine == nil || store == nil {
			http.Error(w, "evidence unavailable", http.StatusServiceUnavailable)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 65<<20)
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			http.Error(w, "invalid multipart form: "+err.Error(), http.StatusBadRequest)
			return
		}
		if r.MultipartForm != nil {
			defer func() {
				if err := r.MultipartForm.RemoveAll(); err != nil {
					slog.Warn("multipart cleanup failed", "error", err)
				}
			}()
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "file required", http.StatusBadRequest)
			return
		}
		defer file.Close()

		inputs := dpEngine.InspectionSnapshot()
		opts := pcap.AnalysisOptions{Rules: inputs.Rules}
		metadata, err := evidenceMetadataFrom(inputs)
		if err != nil {
			evidenceError(w, err)
			return
		}
		decoders, err := inputs.NewDecoders()
		if err != nil {
			evidenceError(w, err)
			return
		}
		result, err := pcap.Import(r.Context(), file, store, metadata, opts, decoders...)
		if err != nil {
			if errors.Is(err, pcap.ErrInvalidCapture) {
				http.Error(w, err.Error(), 400)
			} else {
				evidenceError(w, err)
			}
			return
		}
		writeJSON(w, result)
	}
}

func pcapAnalyzeNameHandler(mgr *pcap.Manager, dpEngine *engine.Engine, store evidence.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if dpEngine == nil || store == nil {
			http.Error(w, "evidence unavailable", http.StatusServiceUnavailable)
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

		inputs := dpEngine.InspectionSnapshot()
		opts := pcap.AnalysisOptions{Rules: inputs.Rules}
		metadata, err := evidenceMetadataFrom(inputs)
		if err != nil {
			evidenceError(w, err)
			return
		}
		decoders, err := inputs.NewDecoders()
		if err != nil {
			evidenceError(w, err)
			return
		}
		result, err := pcap.Import(r.Context(), f, store, metadata, opts, decoders...)
		if err != nil {
			if errors.Is(err, pcap.ErrInvalidCapture) {
				http.Error(w, err.Error(), 400)
			} else {
				evidenceError(w, err)
			}
			return
		}
		writeJSON(w, result)
	}
}
