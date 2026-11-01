// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	engineclient "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/learn"
)

type EvidenceClient interface {
	Learn(context.Context, string, string, string, json.RawMessage) (json.RawMessage, error)
}

func evidenceProxy(store config.Store, engine EngineClient, path string) gin.HandlerFunc {
	return func(c *gin.Context) {
		client, ok := engine.(EvidenceClient)
		if !ok {
			apiError(c, 503, "engine evidence unavailable")
			return
		}
		suffix := path
		if id := c.Param("id"); id != "" {
			suffix = replacePathID(suffix, id)
		}
		if c.Request.URL.RawQuery != "" {
			suffix += "?" + c.Request.URL.RawQuery
		}
		body, err := io.ReadAll(io.LimitReader(c.Request.Body, (1<<20)+1))
		if err != nil || len(body) > 1<<20 {
			apiError(c, 400, "invalid or oversized evidence request")
			return
		}
		response, err := client.Learn(c.Request.Context(), c.Request.Method, suffix, c.GetString("actor"), body)
		if err != nil {
			evidenceHTTPError(c, err)
			return
		}
		if c.Request.Method == "GET" && (path == "/learn/suggestions" || path == "/learn/suggestions/:id") {
			cfg, err := store.Load(c.Request.Context())
			if err != nil {
				internalError(c, err)
				return
			}
			response, err = addLegacyOverlapWarnings(response, cfg.Firewall.Rules, path == "/learn/suggestions")
			if err != nil {
				apiError(c, 503, "invalid engine suggestion response")
				return
			}
		}
		if len(response) == 0 {
			c.Status(http.StatusNoContent)
		} else {
			c.Data(http.StatusOK, "application/json", response)
		}
	}
}
func replacePathID(path, id string) string {
	for i := 0; i+3 <= len(path); i++ {
		if path[i:i+3] == ":id" {
			return path[:i] + url.PathEscape(id) + path[i+3:]
		}
	}
	return path
}
func evidenceHTTPError(c *gin.Context, err error) {
	var status *engineclient.EvidenceError
	if errors.As(err, &status) {
		switch status.Status {
		case 400, 404, 409, 410:
			apiError(c, status.Status, status.Detail)
			return
		}
	}
	apiError(c, 503, "engine evidence unavailable")
}

func applyEvidenceHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		client, ok := engine.(EvidenceClient)
		if !ok {
			apiError(c, 503, "engine evidence unavailable")
			return
		}
		var req learn.ApplyRequest
		decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			apiError(c, 400, "invalid stage request")
			return
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			apiError(c, 400, "one stage request required")
			return
		}
		if req.RequestID == "" || len(req.RequestID) > 128 || len(req.Selections) == 0 || len(req.Selections) > 128 {
			apiError(c, 400, "requestId and 1..128 selections required")
			return
		}
		seen := map[string]bool{}
		for _, s := range req.Selections {
			if s.ID == "" || s.Revision == 0 || seen[s.ID] {
				apiError(c, 400, "unique nonzero-revision selections required")
				return
			}
			seen[s.ID] = true
		}
		body, err := json.Marshal(req)
		if err != nil {
			internalError(c, err)
			return
		}
		frozen, err := client.Learn(c.Request.Context(), http.MethodPost, "/learn/stage/resolve", c.GetString("actor"), body)
		if err != nil {
			evidenceHTTPError(c, err)
			return
		}
		var suggestions []learn.Suggestion
		if err := json.Unmarshal(frozen, &suggestions); err != nil || len(suggestions) != len(req.Selections) {
			apiError(c, 503, "invalid engine stage resolution")
			return
		}
		var rules []config.Rule
		reconcileOnly := false
		for i, s := range suggestions {
			if s.ID != req.Selections[i].ID || s.Revision != req.Selections[i].Revision || s.Proof == nil || s.Proof.ValidateBinding(s.Content) != nil {
				apiError(c, 503, "invalid engine stage resolution")
				return
			}
			reconcileOnly = reconcileOnly || s.StageReconcileOnly || !learn.CompatibleVersions(s.Proof.Versions)
			rules = append(rules, s.Content.Rules...)
		}
		if len(rules) > 128 {
			apiError(c, 409, "stage bundle exceeds rule budget")
			return
		}
		conflict := errors.New("candidate contains conflicting rule content")
		err = store.MutateCandidate(c.Request.Context(), func(cfg *config.Config) error {
			existing := map[string]config.Rule{}
			for _, r := range cfg.Firewall.Rules {
				if _, found := existing[r.ID]; found {
					return conflict
				}
				existing[r.ID] = r
			}
			for _, r := range rules {
				if old, exists := existing[r.ID]; exists {
					a, err := json.Marshal(old)
					if err != nil {
						return err
					}
					b, err := json.Marshal(r)
					if err != nil {
						return err
					}
					if !bytes.Equal(a, b) {
						return conflict
					}
					continue
				}
				if reconcileOnly {
					return learn.ErrStale
				}
				cfg.Firewall.Rules = append(cfg.Firewall.Rules, r)
				existing[r.ID] = r
			}
			return nil
		})
		if err != nil {
			if reconcileOnly {
				apiError(c, 409, "incompatible proof; only identical already-staged rules may be reconciled")
				return
			}
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), 10*time.Second)
			_, releaseErr := client.Learn(cleanup, http.MethodPost, "/learn/stage/release", c.GetString("actor"), body)
			cancel()
			if releaseErr != nil {
				apiError(c, 503, "stage release uncertain; retry requestId "+req.RequestID)
				return
			}
			if errors.Is(err, conflict) {
				apiError(c, 409, err.Error())
			} else {
				apiError(c, 409, "candidate rejected entire stage: "+err.Error())
			}
			return
		}
		configChangeResponse(c, "staged")
		if _, err := client.Learn(c.Request.Context(), http.MethodPost, "/learn/stage/complete", c.GetString("actor"), body); err != nil {
			apiError(c, 503, "candidate durably staged; completion uncertain; retry requestId "+req.RequestID)
			return
		}
		auditLog(c, audit.Record{Action: "learn.apply", Target: req.RequestID, Detail: "candidate"})
		c.JSON(200, gin.H{"requestId": req.RequestID, "selections": req.Selections, "staged": true})
	}
}

func registerEvidenceRoutes(group *gin.RouterGroup, store config.Store, engine EngineClient) {
	for _, route := range []struct{ method, path string }{
		{"POST", "/learn/watches"}, {"GET", "/learn/watches"}, {"GET", "/learn/watches/:id"}, {"POST", "/learn/watches/:id/stop"},
		{"GET", "/learn/datasets"}, {"GET", "/learn/datasets/:id"}, {"GET", "/learn/datasets/:id/observations"}, {"DELETE", "/learn/datasets/:id"},
		{"POST", "/learn/generate"}, {"GET", "/learn/suggestions"}, {"GET", "/learn/suggestions/:id"}, {"POST", "/learn/suggestions/:id/review"}, {"GET", "/learn/counters"},
	} {
		handler := evidenceProxy(store, engine, route.path)
		if route.method == "GET" {
			group.Handle(route.method, route.path, handler)
		} else {
			group.Handle(route.method, route.path, requireAdmin(), handler)
		}
	}
	group.POST("/learn/apply", requireAdmin(), applyEvidenceHandler(store, engine))
}
