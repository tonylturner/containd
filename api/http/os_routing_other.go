// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func getOSRoutingHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "os routing view is only supported on linux"})
	}
}

func detectKernelDefaultRouteIface() string {
	return ""
}
