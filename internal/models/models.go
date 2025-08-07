// Package models defines API request/response and feature model types.
package models

// URLRequest is the request payload holding a batch of URLs to analyze.
type URLRequest struct {
	URLs []string `json:"urls"`
}

// URLFeatures describes properties extracted from the URL string and domain.
type URLFeatures struct {
	DomainLength         int  `json:"domain_length"`
	URLLength            int  `json:"url_length"`
	HasSuspiciousWords   bool `json:"has_suspicious_words"`
	NumSubdomains        int  `json:"num_subdomains"`
	UsesIPAddress        bool `json:"uses_ip_address"`
	UsesInsecureProtocol bool `json:"uses_insecure_protocol"`
	DomainAgeDays        int  `json:"domain_age_days"`
}

// HTMLFeatures describes signals extracted from a page's HTML content.
type HTMLFeatures struct {
	ContentFetched       bool `json:"content_fetched"`
	HasSuspiciousTitle   bool `json:"has_suspicious_title"`
	HasPhishingKeywords  bool `json:"has_phishing_keywords"`
	HasSuspiciousForms   bool `json:"has_suspicious_forms"`
	HasExternalRedirects bool `json:"has_external_redirects"`
	HasObfuscatedCode    bool `json:"has_obfuscated_code"`
	MissingSSLIndicators bool `json:"missing_ssl_indicators"`
	HTMLScore            int  `json:"html_score"`
}

// URLAnalysisResult is the top-level result for a single analyzed URL.
type URLAnalysisResult struct {
	URL         string       `json:"url"`
	Score       int          `json:"score"`
	URLDetails  URLFeatures  `json:"url_details"`
	HTMLDetails HTMLFeatures `json:"html_details"`
	FinalScore  int          `json:"final_score"`
}
