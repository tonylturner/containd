// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/common"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func exportConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := store.Load(c.Request.Context())
		if err != nil {
			if errors.Is(err, config.ErrNotFound) {
				apiError(c, http.StatusNotFound, "config not found")
				return
			}
			internalError(c, err)
			return
		}
		// Exports are redacted by default; only admins can request unredacted.
		wantRedacted := true
		switch strings.ToLower(strings.TrimSpace(c.Query("redacted"))) {
		case "0", "false", "no":
			wantRedacted = false
		case "1", "true", "yes":
			wantRedacted = true
		case "":
			// default redacted
		default:
			apiError(c, http.StatusBadRequest, "invalid redacted query value")
			return
		}
		if !wantRedacted && c.GetString(ctxRoleKey) != string(roleAdmin) {
			apiError(c, http.StatusForbidden, "admin role required for unredacted export")
			return
		}
		if wantRedacted {
			cfg = cfg.RedactedCopy()
		}
		c.JSON(http.StatusOK, cfg)
	}
}

func importConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		const maxImportSize = 10 << 20 // 10 MB
		body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxImportSize+1))
		if err != nil {
			apiError(c, http.StatusBadRequest, "failed to read body")
			return
		}
		if int64(len(body)) > maxImportSize {
			apiError(c, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		var cfg config.Config
		if err := json.Unmarshal(body, &cfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		if err := cfg.Validate(); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := store.Save(c.Request.Context(), &cfg); err != nil {
			internalError(c, err)
			return
		}
		auditLog(c, audit.Record{Action: "config.import", Target: "running"})
		c.JSON(http.StatusOK, gin.H{"status": "imported"})
	}
}

type configBackupMeta struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	CreatedAt    time.Time `json:"createdAt"`
	Redacted     bool      `json:"redacted"`
	IDSRuleCount int       `json:"idsRuleCount,omitempty"`
}

type configBackupInfo struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	CreatedAt    time.Time `json:"createdAt"`
	Redacted     bool      `json:"redacted"`
	Size         int64     `json:"size"`
	IDSRuleCount int       `json:"idsRuleCount,omitempty"`
}

type configBackupRequest struct {
	Name     string `json:"name"`
	Redacted bool   `json:"redacted"`
}

func configBackupDir() string {
	if v := common.EnvTrimmed("CONTAIND_CONFIG_BACKUP_DIR", ""); v != "" {
		return v
	}
	if dbPath := common.EnvTrimmed("CONTAIND_CONFIG_DB", ""); dbPath != "" {
		return filepath.Join(filepath.Dir(dbPath), "config-backups")
	}
	return filepath.Join("data", "config-backups")
}

func configBackupPaths(id string) (string, string) {
	// Sanitize to prevent path traversal: only allow alphanumeric, hyphens, underscores.
	clean := filepath.Base(id)
	for _, r := range clean {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			clean = ""
			break
		}
	}
	if clean == "" || clean == "." || clean == ".." {
		clean = "invalid"
	}
	dir := configBackupDir()
	return filepath.Join(dir, clean+".json"), filepath.Join(dir, clean+".meta.json")
}

func newConfigBackupID() (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

func sanitizeBackupFilename(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "containd-config-backup"
	}
	var out strings.Builder
	out.Grow(len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			out.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			out.WriteRune(r)
		case r >= '0' && r <= '9':
			out.WriteRune(r)
		case r == '-' || r == '_' || r == ' ':
			out.WriteRune(r)
		default:
			out.WriteRune('_')
		}
	}
	return strings.TrimSpace(out.String())
}

func listConfigBackupsHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		dir := configBackupDir()
		entries, err := os.ReadDir(dir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				c.JSON(http.StatusOK, []configBackupInfo{})
				return
			}
			internalError(c, err)
			return
		}
		isAdmin := c.GetString(ctxRoleKey) == string(roleAdmin)
		backups := make([]configBackupInfo, 0, len(entries))
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".meta.json") {
				continue
			}
			metaPath := filepath.Join(dir, entry.Name())
			metaBytes, err := os.ReadFile(metaPath)
			if err != nil {
				continue
			}
			var meta configBackupMeta
			if err := json.Unmarshal(metaBytes, &meta); err != nil {
				continue
			}
			if !isAdmin && !meta.Redacted {
				continue
			}
			jsonPath, _ := configBackupPaths(meta.ID)
			info, err := os.Stat(jsonPath)
			if err != nil {
				continue
			}
			backups = append(backups, configBackupInfo{
				ID:           meta.ID,
				Name:         meta.Name,
				CreatedAt:    meta.CreatedAt,
				Redacted:     meta.Redacted,
				Size:         info.Size(),
				IDSRuleCount: meta.IDSRuleCount,
			})
		}
		sort.Slice(backups, func(i, j int) bool {
			return backups[i].CreatedAt.After(backups[j].CreatedAt)
		})
		c.JSON(http.StatusOK, backups)
	}
}

func createConfigBackupHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req configBackupRequest
		if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
			apiError(c, http.StatusBadRequest, "invalid request")
			return
		}
		cfg, err := store.Load(c.Request.Context())
		if err != nil {
			if errors.Is(err, config.ErrNotFound) {
				apiError(c, http.StatusNotFound, "config not found")
				return
			}
			internalError(c, err)
			return
		}
		if req.Redacted {
			cfg = cfg.RedactedCopy()
		}
		if err := os.MkdirAll(configBackupDir(), 0o750); err != nil {
			internalError(c, err)
			return
		}
		id, err := newConfigBackupID()
		if err != nil {
			apiError(c, http.StatusInternalServerError, "failed to generate backup id")
			return
		}
		now := time.Now().UTC()
		name := strings.TrimSpace(req.Name)
		if name == "" {
			name = fmt.Sprintf("Backup %s", now.Format("2006-01-02 15:04 UTC"))
		}
		idsRules, _ := store.LoadIDSRules(c.Request.Context())
		meta := configBackupMeta{
			ID:           id,
			Name:         name,
			CreatedAt:    now,
			Redacted:     req.Redacted,
			IDSRuleCount: len(idsRules),
		}
		jsonPath, metaPath := configBackupPaths(id)
		idsPath := jsonPath[:len(jsonPath)-len(".json")] + ".ids.json"
		tmpJSON := jsonPath + ".tmp"
		tmpMeta := metaPath + ".tmp"
		tmpIDS := idsPath + ".tmp"
		payload, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			apiError(c, http.StatusInternalServerError, "failed to serialize config")
			return
		}
		if err := os.WriteFile(tmpJSON, payload, 0o600); err != nil {
			apiError(c, http.StatusInternalServerError, "failed to write backup")
			return
		}
		metaBytes, err := json.Marshal(meta)
		if err != nil {
			_ = os.Remove(tmpJSON)
			apiError(c, http.StatusInternalServerError, "failed to write backup metadata")
			return
		}
		if err := os.WriteFile(tmpMeta, metaBytes, 0o600); err != nil {
			_ = os.Remove(tmpJSON)
			apiError(c, http.StatusInternalServerError, "failed to write backup metadata")
			return
		}
		if err := os.Rename(tmpJSON, jsonPath); err != nil {
			_ = os.Remove(tmpJSON)
			_ = os.Remove(tmpMeta)
			apiError(c, http.StatusInternalServerError, "failed to persist backup")
			return
		}
		if err := os.Rename(tmpMeta, metaPath); err != nil {
			_ = os.Remove(jsonPath)
			_ = os.Remove(tmpMeta)
			apiError(c, http.StatusInternalServerError, "failed to persist backup metadata")
			return
		}
		if len(idsRules) > 0 {
			idsPayload, _ := json.MarshalIndent(idsRules, "", "  ")
			if err := os.WriteFile(tmpIDS, idsPayload, 0o600); err == nil {
				_ = os.Rename(tmpIDS, idsPath)
			}
		}
		info, _ := os.Stat(jsonPath)
		auditLog(c, audit.Record{Action: "config.backup.create", Target: "running"})
		c.JSON(http.StatusOK, configBackupInfo{
			ID:           meta.ID,
			Name:         meta.Name,
			CreatedAt:    meta.CreatedAt,
			Redacted:     meta.Redacted,
			Size:         info.Size(),
			IDSRuleCount: meta.IDSRuleCount,
		})
	}
}

func downloadConfigBackupHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := strings.TrimSpace(c.Param("id"))
		if id == "" {
			apiError(c, http.StatusBadRequest, "backup id required")
			return
		}
		_, metaPath := configBackupPaths(id)
		metaBytes, err := os.ReadFile(metaPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				apiError(c, http.StatusNotFound, "backup not found")
				return
			}
			internalError(c, err)
			return
		}
		var meta configBackupMeta
		if err := json.Unmarshal(metaBytes, &meta); err != nil {
			apiError(c, http.StatusInternalServerError, "backup metadata corrupted")
			return
		}
		if !meta.Redacted && c.GetString(ctxRoleKey) != string(roleAdmin) {
			apiError(c, http.StatusForbidden, "admin role required for unredacted backup")
			return
		}
		jsonPath, _ := configBackupPaths(id)
		f, err := os.Open(jsonPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				apiError(c, http.StatusNotFound, "backup not found")
				return
			}
			internalError(c, err)
			return
		}
		defer f.Close()
		filename := sanitizeBackupFilename(meta.Name) + ".json"
		c.Header("Content-Type", "application/json")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
		c.Status(http.StatusOK)
		_, _ = io.Copy(c.Writer, f)
	}
}

func deleteConfigBackupHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := strings.TrimSpace(c.Param("id"))
		if id == "" {
			apiError(c, http.StatusBadRequest, "backup id required")
			return
		}
		jsonPath, metaPath := configBackupPaths(id)
		idsPath := jsonPath[:len(jsonPath)-len(".json")] + ".ids.json"
		if err := os.Remove(metaPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			internalError(c, err)
			return
		}
		if err := os.Remove(jsonPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			internalError(c, err)
			return
		}
		_ = os.Remove(idsPath)
		auditLog(c, audit.Record{Action: "config.backup.delete", Target: "running"})
		c.JSON(http.StatusOK, gin.H{"status": "deleted"})
	}
}
