// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/config"
)

// Preview is the sole branch of the ICS template route that is not a writer.
// Inspect a bounded copy without reporting decode errors: apply requests must
// still pass precondition syntax checks before handler body validation.
func requireICSTemplateRevision() gin.HandlerFunc {
	return func(c *gin.Context) {
		body, err := io.ReadAll(io.LimitReader(c.Request.Body, defaultJSONBodyLimit+1))
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		var envelope struct {
			Preview bool `json:"preview"`
		}
		if err == nil && json.Unmarshal(body, &envelope) == nil && envelope.Preview {
			limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit)(c)
			return
		}
		requireConfigRevision()(c)
	}
}

const revisionHeader = "X-Containd-Revision"
const ifRevisionHeader = "X-Containd-If-Revision"

func configRevisionResponse(c *gin.Context, revision config.Revision) {
	c.Header(revisionHeader, string(revision))
}

// This route middleware runs after authentication and authorization, before
// decoding any request body. The store performs the authoritative comparison.
func requireConfigRevision() gin.HandlerFunc {
	return func(c *gin.Context) {
		values := c.Request.Header.Values(ifRevisionHeader)
		if len(values) == 0 {
			c.AbortWithStatusJSON(http.StatusPreconditionRequired, gin.H{
				"error": "this request must send X-Containd-If-Revision with the revision from the read it is based on",
				"code":  "config_revision_required",
			})
			return
		}
		if len(values) != 1 || !config.Revision(values[0]).Valid() {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "X-Containd-If-Revision must be one configuration revision",
				"code":  "config_revision_malformed",
			})
			return
		}
		limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit)(c)
	}
}

func expectedConfigRevision(c *gin.Context) config.Revision {
	return config.Revision(c.GetHeader(ifRevisionHeader))
}

func revisionMismatchResponse(c *gin.Context, err error) bool {
	var mismatch *config.ErrRevisionMismatch
	if !errors.As(err, &mismatch) {
		return false
	}
	c.JSON(http.StatusPreconditionFailed, gin.H{
		"error":           mismatch.Error(),
		"code":            "config_revision_mismatch",
		"currentRevision": mismatch.CurrentRevision,
	})
	return true
}

func readCandidate(c *gin.Context, store config.Store) (*config.Config, error) {
	snapshot, err := store.ReadSnapshot(c.Request.Context(), config.SnapshotCandidate, true)
	if err != nil {
		return nil, err
	}
	configRevisionResponse(c, snapshot.Revision)
	if snapshot.Candidate == nil {
		return nil, config.ErrNotFound
	}
	return snapshot.Candidate, nil
}

func readRunning(c *gin.Context, store config.Store) (*config.Config, error) {
	snapshot, err := store.ReadSnapshot(c.Request.Context(), config.SnapshotRunning, true)
	if err != nil {
		return nil, err
	}
	configRevisionResponse(c, snapshot.Revision)
	if snapshot.Running == nil {
		return nil, config.ErrNotFound
	}
	return snapshot.Running, nil
}

func readRunningIDS(c *gin.Context, store config.Store) ([]config.IDSRule, error) {
	snapshot, err := store.ReadSnapshot(c.Request.Context(), config.SnapshotIDS, true)
	if err != nil {
		return nil, err
	}
	configRevisionResponse(c, snapshot.Revision)
	return snapshot.IDSRules, nil
}

func readRunningOrDefault(c *gin.Context, store config.Store) (*config.Config, error) {
	cfg, err := readRunning(c, store)
	if errors.Is(err, config.ErrNotFound) {
		return config.DefaultConfig(), nil
	}
	return cfg, err
}
