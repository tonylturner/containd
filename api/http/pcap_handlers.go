// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/pcap"
)

func getPCAPConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := readCandidate(c, store)
		if err != nil {
			httpError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.PCAP)
	}
}

func setPCAPConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req config.PCAPConfig
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := config.ValidatePCAPConfig(req); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		cfg, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			cfg.PCAP = req
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "pcap.set", Target: "candidate", Detail: "candidate"})
		c.JSON(http.StatusOK, cfg.PCAP)
	}
}

func startPCAPHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		runningConfigApplyMu.Lock()
		defer runningConfigApplyMu.Unlock()
		var err error
		var body []byte
		if c.Request.Body != nil {
			body, err = io.ReadAll(c.Request.Body)
			if err != nil {
				apiError(c, http.StatusBadRequest, "failed to read pcap start body")
				return
			}
		}
		var capture config.PCAPConfig
		if strings.TrimSpace(string(body)) != "" {
			if err := json.Unmarshal(body, &capture); err != nil {
				apiError(c, http.StatusBadRequest, "invalid pcap start JSON: "+err.Error())
				return
			}
		} else {
			cfg, err := readRunningOrDefault(c, store)
			if err != nil {
				httpError(c, err)
				return
			}
			capture = cfg.PCAP
		}
		capture.Enabled = true
		if err := config.ValidatePCAPConfig(capture); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		var status pcap.Status
		if engine != nil {
			status, err = engine.StartPcap(c.Request.Context(), capture)
			if err != nil {
				apiError(c, http.StatusBadRequest, err.Error())
				return
			}
		}

		if engine == nil {
			c.JSON(http.StatusOK, gin.H{"status": "pcap start queued"})
			return
		}
		auditLog(c, audit.Record{Action: "pcap.start", Target: "running"})
		c.JSON(http.StatusOK, status)
	}
}

func stopPCAPHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		runningConfigApplyMu.Lock()
		defer runningConfigApplyMu.Unlock()
		if engine == nil {
			c.JSON(http.StatusOK, gin.H{"status": "pcap stop queued"})
			return
		}
		status, err := engine.StopPcap(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "pcap.stop", Target: "running"})
		c.JSON(http.StatusOK, status)
	}
}

func getPCAPStatusHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			c.JSON(http.StatusOK, pcap.Status{Running: false})
			return
		}
		status, err := engine.PcapStatus(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, status)
	}
}

func getPCAPListHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			c.JSON(http.StatusOK, []pcap.Item{})
			return
		}
		items, err := engine.ListPcaps(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, items)
	}
}

func uploadPCAPHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			apiError(c, http.StatusBadRequest, "engine unavailable")
			return
		}
		if err := c.Request.ParseMultipartForm(64 << 20); err != nil {
			apiError(c, http.StatusBadRequest, "invalid multipart form")
			return
		}
		file, header, err := c.Request.FormFile("file")
		if err != nil {
			apiError(c, http.StatusBadRequest, "file required")
			return
		}
		defer file.Close()
		var magic [4]byte
		if _, err := io.ReadFull(file, magic[:]); err != nil {
			apiError(c, http.StatusBadRequest, "file too small or unreadable")
			return
		}
		switch {
		case magic == [4]byte{0xd4, 0xc3, 0xb2, 0xa1}:
		case magic == [4]byte{0xa1, 0xb2, 0xc3, 0xd4}:
		case magic == [4]byte{0x0a, 0x0d, 0x0d, 0x0a}:
		default:
			apiError(c, http.StatusBadRequest, "not a valid pcap/pcapng file")
			return
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			apiError(c, http.StatusInternalServerError, "failed to rewind file")
			return
		}
		item, err := engine.UploadPcap(c.Request.Context(), filepath.Base(header.Filename), file)
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "pcap.upload", Target: item.Name})
		c.JSON(http.StatusOK, item)
	}
}

func downloadPCAPHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := strings.TrimSpace(c.Param("name"))
		if name == "" {
			apiError(c, http.StatusBadRequest, "name required")
			return
		}
		if engine == nil {
			apiError(c, http.StatusBadRequest, "engine unavailable")
			return
		}
		resp, err := engine.DownloadPcap(c.Request.Context(), name)
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		defer resp.Body.Close()
		c.Header("Content-Type", resp.Header.Get("Content-Type"))
		c.Header("Content-Length", resp.Header.Get("Content-Length"))
		c.Header("Content-Disposition", resp.Header.Get("Content-Disposition"))
		_, _ = io.Copy(c.Writer, resp.Body)
	}
}

func deletePCAPHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := strings.TrimSpace(c.Param("name"))
		if name == "" {
			apiError(c, http.StatusBadRequest, "name required")
			return
		}
		if engine == nil {
			apiError(c, http.StatusBadRequest, "engine unavailable")
			return
		}
		if err := engine.DeletePcap(c.Request.Context(), name); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "pcap.delete", Target: name})
		c.Status(http.StatusNoContent)
	}
}

func tagPCAPHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			apiError(c, http.StatusBadRequest, "engine unavailable")
			return
		}
		var req pcap.TagRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := engine.TagPcap(c.Request.Context(), req); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "pcap.tag", Target: req.Name})
		c.Status(http.StatusNoContent)
	}
}

func replayPCAPHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			apiError(c, http.StatusBadRequest, "engine unavailable")
			return
		}
		var req pcap.ReplayRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := engine.ReplayPcap(c.Request.Context(), req); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "pcap.replay", Target: req.Name})
		c.Status(http.StatusAccepted)
	}
}

type PcapImportClient interface {
	AnalyzePcap(context.Context, string, io.Reader) (*pcap.ImportResult, error)
	AnalyzePcapByName(context.Context, string) (*pcap.ImportResult, error)
}

func analyzePCAPUploadHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		client, ok := engine.(PcapImportClient)
		if !ok {
			apiError(c, 503, "engine evidence unavailable")
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 65<<20)
		if err := c.Request.ParseMultipartForm(1 << 20); err != nil {
			apiError(c, 400, "invalid multipart form")
			return
		}
		if c.Request.MultipartForm != nil {
			defer func() {
				if err := c.Request.MultipartForm.RemoveAll(); err != nil {
					slog.Warn("multipart cleanup failed", "error", err)
				}
			}()
		}
		file, header, err := c.Request.FormFile("file")
		if err != nil {
			apiError(c, 400, "file required")
			return
		}
		defer file.Close()
		result, err := client.AnalyzePcap(c.Request.Context(), header.Filename, file)
		if err != nil {
			evidenceHTTPError(c, err)
			return
		}
		auditLog(c, audit.Record{Action: "pcap.analyze", Target: result.Dataset.ID})
		c.JSON(200, result)
	}
}
func analyzePCAPNameHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		client, ok := engine.(PcapImportClient)
		if !ok {
			apiError(c, 503, "engine evidence unavailable")
			return
		}
		result, err := client.AnalyzePcapByName(c.Request.Context(), c.Param("name"))
		if err != nil {
			evidenceHTTPError(c, err)
			return
		}
		auditLog(c, audit.Record{Action: "pcap.analyze", Target: result.Dataset.ID})
		c.JSON(200, result)
	}
}
