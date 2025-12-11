package main

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/containd/containd/pkg/common/logging"
)

type healthResponse struct {
	Status     string `json:"status"`
	Component  string `json:"component"`
	Build      string `json:"build"`
	CommitHash string `json:"commitHash,omitempty"`
}

func main() {
	addr := addrFromEnv("NGFW_ENGINE_ADDR", ":8081")
	logger := logging.New("[engine]")

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)

	logger.Printf("ngfw-engine starting on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Fatalf("server exited: %v", err)
	}
}

func addrFromEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	resp := healthResponse{
		Status:    "ok",
		Component: "ngfw-engine",
		Build:     "dev",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
