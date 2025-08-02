package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"hades/internal/models"
)

func TestAnalyzeHandler_ValidRequest(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    models.URLRequest
		expectedStatus int
		expectedCount  int
	}{
		{
			name: "single URL",
			requestBody: models.URLRequest{
				URLs: []string{"https://example.com"},
			},
			expectedStatus: http.StatusOK,
			expectedCount:  1,
		},
		{
			name: "multiple URLs",
			requestBody: models.URLRequest{
				URLs: []string{
					"https://example.com",
					"http://test.org",
					"https://secure.bank.com",
				},
			},
			expectedStatus: http.StatusOK,
			expectedCount:  3,
		},
		{
			name: "empty URLs array",
			requestBody: models.URLRequest{
				URLs: []string{},
			},
			expectedStatus: http.StatusOK,
			expectedCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal request body to JSON
			jsonBody, err := json.Marshal(tt.requestBody)
			if err != nil {
				t.Fatalf("Failed to marshal request body: %v", err)
			}

			// Create HTTP request
			req, err := http.NewRequest("POST", "/analyze", bytes.NewBuffer(jsonBody))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")

			// Create response recorder
			rr := httptest.NewRecorder()

			// Call the handler
			AnalyzeHandler(rr, req)

			// Check status code
			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, status)
			}

			// Check content type
			expectedContentType := "application/json"
			if contentType := rr.Header().Get("Content-Type"); contentType != expectedContentType {
				t.Errorf("Expected content type %s, got %s", expectedContentType, contentType)
			}

			// Parse response body
			var results []models.URLAnalysisResult
			err = json.Unmarshal(rr.Body.Bytes(), &results)
			if err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			// Check number of results
			if len(results) != tt.expectedCount {
				t.Errorf("Expected %d results, got %d", tt.expectedCount, len(results))
			}

			// Validate each result
			for i, result := range results {
				if i >= len(tt.requestBody.URLs) {
					t.Errorf("More results than input URLs")
					break
				}

				expectedURL := tt.requestBody.URLs[i]
				if result.URL != expectedURL {
					t.Errorf("Result[%d] URL: expected %s, got %s", i, expectedURL, result.URL)
				}

				// Score should be non-negative integer
				if result.Score < 0 {
					t.Errorf("Result[%d] Score should be non-negative, got %d", i, result.Score)
				}

				// Details should have reasonable values
				if result.Details.DomainLength < 0 {
					t.Errorf("Result[%d] DomainLength should be non-negative, got %d", i, result.Details.DomainLength)
				}
				if result.Details.URLLength < 0 {
					t.Errorf("Result[%d] URLLength should be non-negative, got %d", i, result.Details.URLLength)
				}
			}
		})
	}
}

func TestAnalyzeHandler_InvalidJSON(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    string
		expectedStatus int
	}{
		{
			name:           "malformed JSON",
			requestBody:    `{"urls": [}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "empty body",
			requestBody:    "",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid JSON structure",
			requestBody:    `{"invalid": "structure"}`,
			expectedStatus: http.StatusOK, // Will succeed with empty URLs array
		},
		{
			name:           "non-JSON content",
			requestBody:    "not json at all",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create HTTP request
			req, err := http.NewRequest("POST", "/analyze", strings.NewReader(tt.requestBody))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")

			// Create response recorder
			rr := httptest.NewRecorder()

			// Call the handler
			AnalyzeHandler(rr, req)

			// Check status code
			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, status)
			}

			// For bad requests, response should contain error message
			if tt.expectedStatus == http.StatusBadRequest {
				if rr.Body.Len() == 0 {
					t.Error("Expected error message in response body for bad request")
				}
			}
		})
	}
}

func TestAnalyzeHandler_HTTPMethods(t *testing.T) {
	methods := []string{"GET", "PUT", "DELETE", "PATCH"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			// Provide empty JSON body to prevent nil pointer dereference
			req, err := http.NewRequest(method, "/analyze", strings.NewReader("{}"))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			AnalyzeHandler(rr, req)

			// The handler doesn't explicitly check HTTP method,
			// so it will try to decode the body and should succeed with empty JSON
			// This tests the handler's behavior with different methods
			if rr.Code != http.StatusBadRequest && rr.Code != http.StatusOK {
				t.Errorf("Unexpected status code for %s method: %d", method, rr.Code)
			}
		})
	}
}

func TestAnalyzeHandler_SuspiciousURLs(t *testing.T) {
	suspiciousURLs := []string{
		"http://login.fake-bank.com",
		"https://secure-verify-account.com",
		"http://192.168.1.1/update",
		"https://sub1.sub2.sub3.sub4.example.com",
	}

	requestBody := models.URLRequest{URLs: suspiciousURLs}
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	req, err := http.NewRequest("POST", "/analyze", bytes.NewBuffer(jsonBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	AnalyzeHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, status)
	}

	var results []models.URLAnalysisResult
	err = json.Unmarshal(rr.Body.Bytes(), &results)
	if err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if len(results) != len(suspiciousURLs) {
		t.Errorf("Expected %d results, got %d", len(suspiciousURLs), len(results))
	}

	// Check that suspicious URLs get higher scores
	for i, result := range results {
		if result.Score == 0 {
			t.Logf("Warning: Suspicious URL %s got score 0, expected higher score", suspiciousURLs[i])
		}

		// Verify the URL matches
		if result.URL != suspiciousURLs[i] {
			t.Errorf("Result[%d] URL mismatch: expected %s, got %s", i, suspiciousURLs[i], result.URL)
		}
	}
}

func TestAnalyzeHandler_LargeRequest(t *testing.T) {
	// Test with many URLs
	urls := make([]string, 100)
	for i := 0; i < 100; i++ {
		urls[i] = "https://example" + string(rune('a'+i%26)) + ".com"
	}

	requestBody := models.URLRequest{URLs: urls}
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	req, err := http.NewRequest("POST", "/analyze", bytes.NewBuffer(jsonBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	AnalyzeHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, status)
	}

	var results []models.URLAnalysisResult
	err = json.Unmarshal(rr.Body.Bytes(), &results)
	if err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if len(results) != 100 {
		t.Errorf("Expected 100 results, got %d", len(results))
	}
}

// Benchmark tests
func BenchmarkAnalyzeHandler_SingleURL(b *testing.B) {
	requestBody := models.URLRequest{
		URLs: []string{"https://example.com"},
	}
	jsonBody, _ := json.Marshal(requestBody)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("POST", "/analyze", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		AnalyzeHandler(rr, req)
	}
}

func BenchmarkAnalyzeHandler_MultipleURLs(b *testing.B) {
	requestBody := models.URLRequest{
		URLs: []string{
			"https://example.com",
			"http://test.org",
			"https://secure.bank.com",
			"http://login.verify.com",
			"https://update.example.net",
		},
	}
	jsonBody, _ := json.Marshal(requestBody)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("POST", "/analyze", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		AnalyzeHandler(rr, req)
	}
}
