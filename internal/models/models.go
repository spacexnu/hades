// Package models defines data structures for URL analysis requests and results.
package models

// URLRequest represents a request containing URLs to be analyzed.
type URLRequest struct {
	URLs []string `json:"urls"`
}

// URLFeatures represents the extracted features from a URL for analysis.
type URLFeatures struct {
	DomainLength         int  `json:"domain_length"`
	URLLength            int  `json:"url_length"`
	HasSuspiciousWords   bool `json:"has_suspicious_words"`
	NumSubdomains        int  `json:"num_subdomains"`
	UsesIPAddress        bool `json:"uses_ip_address"`
	UsesInsecureProtocol bool `json:"uses_insecure_protocol"`
	DomainAgeDays        int  `json:"domain_age_days"`
}

// URLAnalysisResult represents the result of analyzing a URL including its score and features.
type URLAnalysisResult struct {
	URL     string      `json:"url"`
	Score   int         `json:"score"`
	Details URLFeatures `json:"details"`
}
