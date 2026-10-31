// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/users"
)

func listUsersHandler(store users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if store == nil {
			apiError(c, http.StatusServiceUnavailable, "user store unavailable")
			return
		}
		us, err := store.List(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, us)
	}
}

type createUserRequest struct {
	Username  string `json:"username"`
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
	Email     string `json:"email,omitempty"`
	Role      string `json:"role"`
	Password  string `json:"password"`
}

func createUserHandler(store users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if store == nil {
			apiError(c, http.StatusServiceUnavailable, "user store unavailable")
			return
		}
		var req createUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, "invalid JSON")
			return
		}
		u := users.User{
			Username:  req.Username,
			FirstName: req.FirstName,
			LastName:  req.LastName,
			Email:     req.Email,
			Role:      req.Role,
		}
		created, err := store.Create(c.Request.Context(), u, req.Password)
		if err != nil {
			code := http.StatusBadRequest
			if err == users.ErrUsernameTaken {
				code = http.StatusConflict
			}
			apiError(c, code, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "auth.user.create", Target: created.Username, Detail: "role=" + created.Role})
		c.JSON(http.StatusOK, created)
	}
}

func updateUserHandler(store users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if store == nil {
			apiError(c, http.StatusServiceUnavailable, "user store unavailable")
			return
		}
		id := c.Param("id")
		var patch users.Patch
		if err := c.ShouldBindJSON(&patch); err != nil {
			apiError(c, http.StatusBadRequest, "invalid JSON")
			return
		}
		updated, err := store.Update(c.Request.Context(), id, patch)
		if err != nil {
			code := http.StatusBadRequest
			if err == users.ErrNotFound {
				code = http.StatusNotFound
			}
			apiError(c, code, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "auth.user.update", Target: updated.Username, Detail: "role=" + updated.Role})
		c.JSON(http.StatusOK, updated)
	}
}

type setPasswordRequest struct {
	Password string `json:"password"`
}

func setUserPasswordHandler(store users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := users.CheckPasswordChange(); err != nil {
			apiError(c, http.StatusForbidden, err.Error())
			return
		}
		if store == nil {
			apiError(c, http.StatusServiceUnavailable, "user store unavailable")
			return
		}
		var req setPasswordRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, "invalid JSON")
			return
		}
		u, err := store.GetByID(c.Request.Context(), c.Param("id"))
		if err != nil {
			apiError(c, setPasswordErrorStatus(err), err.Error())
			return
		}
		// SetPassword also revokes the account's sessions, except the
		// caller's own when an admin sets their own password here.
		if err := store.SetPassword(c.Request.Context(), u.ID, req.Password); err != nil {
			apiError(c, setPasswordErrorStatus(err), err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "auth.password.set_admin", Target: u.Username})
		c.JSON(http.StatusOK, gin.H{"status": "password_set"})
	}
}

// setPasswordErrorStatus maps a users.Store SetPassword error to its HTTP status.
func setPasswordErrorStatus(err error) int {
	switch {
	case errors.Is(err, users.ErrPasswordChangeLabMode):
		return http.StatusForbidden
	case errors.Is(err, users.ErrNotFound):
		return http.StatusNotFound
	default:
		return http.StatusBadRequest
	}
}

func deleteUserHandler(store users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if store == nil {
			apiError(c, http.StatusServiceUnavailable, "user store unavailable")
			return
		}
		u, err := store.GetByID(c.Request.Context(), c.Param("id"))
		if err == nil {
			err = store.Delete(c.Request.Context(), u.ID)
		}
		if err != nil {
			code := http.StatusBadRequest
			switch {
			case errors.Is(err, users.ErrNotFound):
				code = http.StatusNotFound
			case errors.Is(err, users.ErrLastAdmin):
				code = http.StatusConflict
			}
			apiError(c, code, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "auth.user.delete", Target: u.Username})
		c.JSON(http.StatusOK, gin.H{"status": "deleted"})
	}
}
