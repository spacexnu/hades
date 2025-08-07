// Package api exposes HTTP handlers for the HADES service.
package api

import (
	"encoding/json"
	"net/http"

	"hades/internal/analyzer"
	"hades/internal/models"
)

// AnalyzeHandler accepts a list of URLs and returns analysis results as JSON.
func AnalyzeHandler(w http.ResponseWriter, r *http.Request) {
	var req models.URLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	results := []models.URLAnalysisResult{}
	for _, u := range req.URLs {
		result := analyzer.PerformComprehensiveAnalysis(u)
		results = append(results, result)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(results); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// HealthHandler returns a simple health-check response.
func HealthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
		// Log error but don't return since headers are already written
		return
	}
}
