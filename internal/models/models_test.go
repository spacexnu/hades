package models

import (
	"encoding/json"
	"testing"
)

func TestURLRequest_JSONMarshaling(t *testing.T) {
	tests := []struct {
		name     string
		request  URLRequest
		expected string
	}{
		{
			name:     "empty URLs",
			request:  URLRequest{URLs: []string{}},
			expected: `{"urls":[]}`,
		},
		{
			name:     "single URL",
			request:  URLRequest{URLs: []string{"https://example.com"}},
			expected: `{"urls":["https://example.com"]}`,
		},
		{
			name:     "multiple URLs",
			request:  URLRequest{URLs: []string{"https://example.com", "http://test.org"}},
			expected: `{"urls":["https://example.com","http://test.org"]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData, err := json.Marshal(tt.request)
			if err != nil {
				t.Fatalf("Failed to marshal URLRequest: %v", err)
			}
			if string(jsonData) != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, string(jsonData))
			}
		})
	}
}

func TestURLRequest_JSONUnmarshaling(t *testing.T) {
	tests := []struct {
		name     string
		jsonData string
		expected URLRequest
		wantErr  bool
	}{
		{
			name:     "valid empty URLs",
			jsonData: `{"urls":[]}`,
			expected: URLRequest{URLs: []string{}},
			wantErr:  false,
		},
		{
			name:     "valid single URL",
			jsonData: `{"urls":["https://example.com"]}`,
			expected: URLRequest{URLs: []string{"https://example.com"}},
			wantErr:  false,
		},
		{
			name:     "valid multiple URLs",
			jsonData: `{"urls":["https://example.com","http://test.org"]}`,
			expected: URLRequest{URLs: []string{"https://example.com", "http://test.org"}},
			wantErr:  false,
		},
		{
			name:     "invalid JSON",
			jsonData: `{"urls":}`,
			expected: URLRequest{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var request URLRequest
			err := json.Unmarshal([]byte(tt.jsonData), &request)
			if (err != nil) != tt.wantErr {
				t.Errorf("Expected error: %v, got: %v", tt.wantErr, err)
				return
			}
			if !tt.wantErr {
				if len(request.URLs) != len(tt.expected.URLs) {
					t.Errorf("Expected %d URLs, got %d", len(tt.expected.URLs), len(request.URLs))
					return
				}
				for i, url := range request.URLs {
					if url != tt.expected.URLs[i] {
						t.Errorf("Expected URL[%d] = %s, got %s", i, tt.expected.URLs[i], url)
					}
				}
			}
		})
	}
}

func TestURLFeatures_JSONMarshaling(t *testing.T) {
	features := URLFeatures{
		DomainLength:         15,
		URLLength:            50,
		HasSuspiciousWords:   true,
		NumSubdomains:        2,
		UsesIPAddress:        false,
		UsesInsecureProtocol: true,
		DomainAgeDays:        365,
	}

	jsonData, err := json.Marshal(features)
	if err != nil {
		t.Fatalf("Failed to marshal URLFeatures: %v", err)
	}

	expected := `{"domain_length":15,"url_length":50,"has_suspicious_words":true,"num_subdomains":2,"uses_ip_address":false,"uses_insecure_protocol":true,"domain_age_days":365}`
	if string(jsonData) != expected {
		t.Errorf("Expected %s, got %s", expected, string(jsonData))
	}
}

func TestURLFeatures_JSONUnmarshaling(t *testing.T) {
	jsonData := `{"domain_length":15,"url_length":50,"has_suspicious_words":true,"num_subdomains":2,"uses_ip_address":false,"uses_insecure_protocol":true,"domain_age_days":365}`

	var features URLFeatures
	err := json.Unmarshal([]byte(jsonData), &features)
	if err != nil {
		t.Fatalf("Failed to unmarshal URLFeatures: %v", err)
	}

	expected := URLFeatures{
		DomainLength:         15,
		URLLength:            50,
		HasSuspiciousWords:   true,
		NumSubdomains:        2,
		UsesIPAddress:        false,
		UsesInsecureProtocol: true,
		DomainAgeDays:        365,
	}

	if features != expected {
		t.Errorf("Expected %+v, got %+v", expected, features)
	}
}

func TestURLAnalysisResult_JSONMarshaling(t *testing.T) {
	result := URLAnalysisResult{
		URL:   "https://example.com",
		Score: 75,
		URLDetails: URLFeatures{
			DomainLength:         11,
			URLLength:            19,
			HasSuspiciousWords:   false,
			NumSubdomains:        0,
			UsesIPAddress:        false,
			UsesInsecureProtocol: false,
			DomainAgeDays:        1000,
		},
		HTMLDetails: HTMLFeatures{
			ContentFetched:       true,
			HasSuspiciousTitle:   false,
			HasPhishingKeywords:  false,
			HasSuspiciousForms:   false,
			HasExternalRedirects: false,
			HasObfuscatedCode:    false,
			MissingSSLIndicators: false,
			HTMLScore:            0,
		},
		FinalScore: 30,
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal URLAnalysisResult: %v", err)
	}

	// Just check that it marshals without error and contains expected fields
	var unmarshaled map[string]interface{}
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	if unmarshaled["url"] != "https://example.com" {
		t.Errorf("Expected URL to be https://example.com, got %v", unmarshaled["url"])
	}
	if unmarshaled["score"] != float64(75) {
		t.Errorf("Expected score to be 75, got %v", unmarshaled["score"])
	}
	if unmarshaled["final_score"] != float64(30) {
		t.Errorf("Expected final_score to be 30, got %v", unmarshaled["final_score"])
	}
}

func TestURLAnalysisResult_JSONUnmarshaling(t *testing.T) {
	jsonData := `{"url":"https://example.com","score":75,"url_details":{"domain_length":11,"url_length":19,"has_suspicious_words":false,"num_subdomains":0,"uses_ip_address":false,"uses_insecure_protocol":false,"domain_age_days":1000},"html_details":{"content_fetched":true,"has_suspicious_title":false,"has_phishing_keywords":false,"has_suspicious_forms":false,"has_external_redirects":false,"has_obfuscated_code":false,"missing_ssl_indicators":false,"html_score":0},"final_score":30}`

	var result URLAnalysisResult
	err := json.Unmarshal([]byte(jsonData), &result)
	if err != nil {
		t.Fatalf("Failed to unmarshal URLAnalysisResult: %v", err)
	}

	if result.URL != "https://example.com" {
		t.Errorf("Expected URL to be https://example.com, got %s", result.URL)
	}
	if result.Score != 75 {
		t.Errorf("Expected Score to be 75, got %d", result.Score)
	}
	if result.FinalScore != 30 {
		t.Errorf("Expected FinalScore to be 30, got %d", result.FinalScore)
	}
	if !result.HTMLDetails.ContentFetched {
		t.Errorf("Expected HTMLDetails.ContentFetched to be true, got %v", result.HTMLDetails.ContentFetched)
	}
}
