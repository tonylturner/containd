// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/enforce"
)

// Reuse the compiler's ordered shadow analysis and the existing warning
// header; authoring responses retain their domain-specific JSON shapes.
func candidateShadowWarnings(c *gin.Context, cfg *config.Config) bool {
	snap, err := compile.CompileSnapshot(cfg)
	if err != nil {
		internalError(c, err)
		return false
	}
	var messages []string
	for _, w := range enforce.NewCompiler().RuleWarnings(&snap) {
		if w.ShadowedBy != "" {
			messages = append(messages, w.RuleID+": "+w.Message)
		}
	}
	setWarningHeader(c, messages)
	return true
}
