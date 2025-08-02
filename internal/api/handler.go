// Package api provides HTTP handlers for the HADES URL analysis service.
package api

import (
	"encoding/json"
	"net/http"

	"hades/internal/analyzer"
	"hades/internal/models"
)

// AnalyzeHandler handles URL analysis requests and returns analysis results.
func AnalyzeHandler(w http.ResponseWriter, r *http.Request) {
	var req models.URLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	results := []models.URLAnalysisResult{}
	for _, u := range req.URLs {
		features := analyzer.ExtractFeatures(u)
		score := analyzer.EvaluateHeuristics(features)
		results = append(results, models.URLAnalysisResult{
			URL:     u,
			Score:   score,
			Details: features,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(results); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// HealthHandler handles health check requests and returns service status.
func HealthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
		// Log error but don't return since headers are already written
		return
	}
}
