// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"net/http"

	"github.com/tonylturner/containd/pkg/cp/users"
	"github.com/gin-gonic/gin"
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
		var patch users.User
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
		c.JSON(http.StatusOK, updated)
	}
}

type setPasswordRequest struct {
	Password string `json:"password"`
}

func setUserPasswordHandler(store users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if store == nil {
			apiError(c, http.StatusServiceUnavailable, "user store unavailable")
			return
		}
		id := c.Param("id")
		var req setPasswordRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, "invalid JSON")
			return
		}
		if err := store.SetPassword(c.Request.Context(), id, req.Password); err != nil {
			code := http.StatusBadRequest
			if err == users.ErrNotFound {
				code = http.StatusNotFound
			}
			apiError(c, code, err.Error())
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "password_set"})
	}
}

func deleteUserHandler(store users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if store == nil {
			apiError(c, http.StatusServiceUnavailable, "user store unavailable")
			return
		}
		id := c.Param("id")
		if err := store.Delete(c.Request.Context(), id); err != nil {
			code := http.StatusBadRequest
			switch err {
			case users.ErrNotFound:
				code = http.StatusNotFound
			case users.ErrLastAdmin:
				code = http.StatusConflict
			}
			apiError(c, code, err.Error())
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "deleted"})
	}
}
