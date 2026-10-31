// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// configCollectionJSON keeps empty list responses authoritative without
// changing the stored candidate's representation.
func configCollectionJSON[T any](c *gin.Context, values []T) {
	if values == nil {
		values = []T{}
	}
	c.JSON(http.StatusOK, values)
}
