// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRevisionResponseWritePaths(t *testing.T) {
	for _, status := range []int{200, 400, 401, 403, 404, 409, 412, 428, 429, 500, 503} {
		for name, write := range map[string]func(*gin.Context){
			"implicit": func(*gin.Context) {},
			"explicit": func(c *gin.Context) { c.Writer.WriteHeaderNow() },
			"bytes":    func(c *gin.Context) { _, _ = c.Writer.Write([]byte("body")) },
			"string":   func(c *gin.Context) { _, _ = c.Writer.WriteString("body") },
			"flush":    func(c *gin.Context) { c.Writer.Flush() },
			"json":     func(c *gin.Context) { c.JSON(status, gin.H{"error": "failure"}) },
		} {
			t.Run(fmt.Sprintf("%d/%s", status, name), func(t *testing.T) {
				router := gin.New()
				router.Use(revisionResponseHeaders())
				router.GET("/", func(c *gin.Context) {
					c.Status(status)
					// Set after Status too: suppression belongs at commit.
					c.Header(revisionHeader, "0123456789abcdef.1")
					c.Header("X-Containd-Config", "staged")
					write(c)
				})
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
				if rec.Code != status {
					t.Fatalf("status %d, want %d", rec.Code, status)
				}
				want := ""
				if status < 400 {
					want = "0123456789abcdef.1"
				}
				if rec.Result().Header.Get(revisionHeader) != want {
					t.Fatalf("revision header %q, want %q", rec.Result().Header.Get(revisionHeader), want)
				}
				if rec.Result().Header.Get("X-Containd-Config") != "staged" {
					t.Fatal("suppression removed the durable staging marker")
				}
			})
		}
	}
}

func TestRevisionResponseRecoveredPanic(t *testing.T) {
	store := stageStore(t)
	server := NewServer(store, nil)
	server.GET("/panic-after-read", func(c *gin.Context) {
		if _, err := readCandidate(c, store); err != nil {
			t.Fatal(err)
		}
		panic("after config read")
	})
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panic-after-read", nil))
	if rec.Code != http.StatusInternalServerError || rec.Result().Header.Get(revisionHeader) != "" {
		t.Fatalf("recovered panic: status %d, headers %v", rec.Code, rec.Result().Header)
	}
}

func TestRevisionResponseDefaultErrors(t *testing.T) {
	server := gin.New()
	server.HandleMethodNotAllowed = true
	server.Use(revisionResponseHeaders())
	server.GET("/present", func(c *gin.Context) { c.Status(http.StatusOK) })
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{http.MethodGet, "/missing", "404 page not found", http.StatusNotFound},
		{http.MethodPost, "/present", "405 method not allowed", http.StatusMethodNotAllowed},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			rec.Header().Set(revisionHeader, "0123456789abcdef.1")
			server.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
			if rec.Code != tc.status || rec.Body.String() != tc.body || rec.Result().Header.Get(revisionHeader) != "" {
				t.Fatalf("default error: status %d, body %q, headers %v", rec.Code, rec.Body.String(), rec.Result().Header)
			}
		})
	}
}
