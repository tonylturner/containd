// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Install before recovery so even recovered panics obey the response contract.
// A handler may read config before failing; only successful responses can
// acknowledge that read's revision.
func revisionResponseHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		writer := &revisionResponseWriter{ResponseWriter: c.Writer}
		c.Writer = writer
		c.Next()
		// Gin's final implicit header write bypasses c.Writer. Prepare its
		// headers without committing: Gin may still supply a default body.
		writer.stripErrorRevision()
	}
}

type revisionResponseWriter struct {
	gin.ResponseWriter
}

func (w *revisionResponseWriter) stripErrorRevision() {
	if !w.Written() && w.Status() >= http.StatusBadRequest {
		w.Header().Del(revisionHeader)
	}
}

func (w *revisionResponseWriter) WriteHeaderNow() {
	w.stripErrorRevision()
	w.ResponseWriter.WriteHeaderNow()
}

func (w *revisionResponseWriter) Write(body []byte) (int, error) {
	w.WriteHeaderNow()
	return w.ResponseWriter.Write(body)
}

func (w *revisionResponseWriter) WriteString(body string) (int, error) {
	w.WriteHeaderNow()
	return w.ResponseWriter.WriteString(body)
}

func (w *revisionResponseWriter) Flush() {
	w.WriteHeaderNow()
	w.ResponseWriter.Flush()
}
