// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/dp/signatures"
)

func learnProfilesHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		lc, ok := engine.(LearnClient)
		if !ok || lc == nil {
			c.JSON(http.StatusOK, []learn.LearnedProfile{})
			return
		}
		profiles, err := lc.ListLearnProfiles(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		if profiles == nil {
			profiles = []learn.LearnedProfile{}
		}
		c.JSON(http.StatusOK, profiles)
	}
}

func learnGenerateHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		lc, ok := engine.(LearnClient)
		if !ok || lc == nil {
			c.JSON(http.StatusOK, []config.Rule{})
			return
		}
		genRules, err := lc.GenerateLearnRules(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, genRules)
	}
}

func learnApplyHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		lc, ok := engine.(LearnClient)
		if !ok || lc == nil {
			apiError(c, http.StatusBadRequest, "learn mode not available")
			return
		}
		generated, err := lc.GenerateLearnRules(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		if len(generated) == 0 {
			c.JSON(http.StatusOK, gin.H{"status": "no rules to apply", "count": 0})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		existing := map[string]bool{}
		for _, r := range cfg.Firewall.Rules {
			existing[r.ID] = true
		}
		added := 0
		for _, r := range generated {
			if existing[r.ID] {
				continue
			}
			cfg.Firewall.Rules = append(cfg.Firewall.Rules, r)
			added++
		}
		if cfg.Firewall.DefaultAction == "" {
			cfg.Firewall.DefaultAction = config.ActionDeny
		}
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "applied", "count": added, "rules": generated})
	}
}

func learnClearHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		lc, ok := engine.(LearnClient)
		if !ok || lc == nil {
			c.JSON(http.StatusOK, gin.H{"status": "cleared"})
			return
		}
		if err := lc.ClearLearnData(c.Request.Context()); err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "cleared"})
	}
}

func listSignaturesHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		sc, ok := engine.(SignaturesClient)
		if !ok || sc == nil {
			c.JSON(http.StatusOK, []signatures.Signature{})
			return
		}
		sigs, err := sc.ListSignatures(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		if sigs == nil {
			sigs = []signatures.Signature{}
		}
		c.JSON(http.StatusOK, sigs)
	}
}

func addSignatureHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		sc, ok := engine.(SignaturesClient)
		if !ok || sc == nil {
			apiError(c, http.StatusNotImplemented, "signatures not available")
			return
		}
		var sig signatures.Signature
		if err := c.ShouldBindJSON(&sig); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if sig.ID == "" {
			apiError(c, http.StatusBadRequest, "signature ID is required")
			return
		}
		if len(sig.Conditions) == 0 {
			apiError(c, http.StatusBadRequest, "at least one condition is required")
			return
		}
		if err := sc.AddSignature(c.Request.Context(), sig); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "signatures.add", Target: sig.ID})
		c.JSON(http.StatusOK, sig)
	}
}

func deleteSignatureHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		sc, ok := engine.(SignaturesClient)
		if !ok || sc == nil {
			apiError(c, http.StatusNotImplemented, "signatures not available")
			return
		}
		id := c.Param("id")
		removed, err := sc.RemoveSignature(c.Request.Context(), id)
		if err != nil {
			internalError(c, err)
			return
		}
		if !removed {
			apiError(c, http.StatusNotFound, "signature not found")
			return
		}
		auditLog(c, audit.Record{Action: "signatures.delete", Target: id})
		c.Status(http.StatusNoContent)
	}
}

func listSignatureMatchesHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		sc, ok := engine.(SignaturesClient)
		if !ok || sc == nil {
			c.JSON(http.StatusOK, []signatures.Match{})
			return
		}
		limit := 100
		if v := c.Query("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}
		matches, err := sc.ListSignatureMatches(c.Request.Context(), limit)
		if err != nil {
			internalError(c, err)
			return
		}
		if matches == nil {
			matches = []signatures.Match{}
		}
		c.JSON(http.StatusOK, matches)
	}
}
