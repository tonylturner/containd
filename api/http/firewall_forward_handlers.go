// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func publishPortForwardHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Forward   config.PortForward `json:"forward"`
			AllowRule *bool              `json:"allowRule"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || req.Forward.ID == "" {
			apiError(c, 400, "forward with an id is required")
			return
		}
		var placement *config.ForwardPlacement
		_, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			for _, f := range cfg.Firewall.NAT.PortForwards {
				if f.ID == req.Forward.ID {
					apiError(c, 400, "port forward already exists")
					return false
				}
			}
			cfg.Firewall.NAT.PortForwards = append(cfg.Firewall.NAT.PortForwards, req.Forward)
			if req.AllowRule == nil || *req.AllowRule {
				p := config.ForwardAllowPlacement(cfg, req.Forward)
				placement = &p
				if p.Rule != nil {
					cfg.Firewall.Rules = insertRule(cfg.Firewall.Rules, p.Index, *p.Rule)
				}
			}
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "firewall.port_forward.publish", Target: req.Forward.ID, Detail: "candidate"})
		c.JSON(200, struct {
			Forward   config.PortForward       `json:"forward"`
			Placement *config.ForwardPlacement `json:"placement,omitempty"`
		}{req.Forward, placement})
	}
}

func deletePortForwardHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		deleted, edited := []string{}, []string{}
		_, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			i := slices.IndexFunc(cfg.Firewall.NAT.PortForwards, func(f config.PortForward) bool { return f.ID == id })
			if i < 0 {
				apiError(c, 404, "port forward not found")
				return false
			}
			cfg.Firewall.NAT.PortForwards = slices.Delete(cfg.Firewall.NAT.PortForwards, i, i+1)
			list := make([]config.Rule, 0, len(cfg.Firewall.Rules))
			for _, r := range cfg.Firewall.Rules {
				if slices.Contains(r.ViaForwards, id) {
					r.ViaForwards = slices.DeleteFunc(r.ViaForwards, func(ref string) bool { return ref == id })
					if len(r.ViaForwards) == 0 {
						deleted = append(deleted, r.ID)
						continue
					}
					edited = append(edited, r.ID)
				}
				list = append(list, r)
			}
			cfg.Firewall.Rules = list
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "firewall.port_forward.delete", Target: id, Detail: "candidate"})
		c.JSON(200, gin.H{"deletedRuleIds": deleted, "editedRuleIds": edited})
	}
}
