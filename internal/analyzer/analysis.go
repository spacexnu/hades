// Package analyzer provides URL analysis functionality including feature extraction and heuristic evaluation.
package analyzer

import (
	"net"
	"net/url"
	"strings"

	"hades/internal/models"
)

// ExtractFeatures parses a raw URL and produces URLFeatures populated with heuristic inputs.
func ExtractFeatures(rawURL string) models.URLFeatures {
	parsed, _ := url.Parse(rawURL)
	domain := parsed.Hostname()
	age := GetDomainAgeDays(domain)

	return models.URLFeatures{
		DomainLength:         len(domain),
		URLLength:            len(rawURL),
		HasSuspiciousWords:   containsSuspiciousWord(rawURL),
		NumSubdomains:        len(strings.Split(domain, ".")) - 2,
		UsesIPAddress:        isIPAddress(domain),
		UsesInsecureProtocol: parsed.Scheme == "http",
		DomainAgeDays:        age,
	}
}

// EvaluateHeuristics scores URL-only signals producing a partial risk score.
func EvaluateHeuristics(f models.URLFeatures) int {
	score := 0
	if f.UsesInsecureProtocol {
		score += 10
	}
	if f.HasSuspiciousWords {
		score += 20
	}
	if f.NumSubdomains > 3 {
		score += 5
	}
	if f.UsesIPAddress {
		score += 25
	}
	if f.DomainAgeDays >= 0 && f.DomainAgeDays < 30 {
		score += 50
	}
	return score
}

func containsSuspiciousWord(u string) bool {
	keywords := []string{"login", "verify", "update", "secure", "bank"}
	for _, k := range keywords {
		if strings.Contains(strings.ToLower(u), k) {
			return true
		}
	}
	return false
}

func isIPAddress(host string) bool {
	if host == "" {
		return false
	}

	// Try to parse as IP address
	ip := net.ParseIP(host)
	return ip != nil
}

// PerformComprehensiveAnalysis runs URL and HTML analysis and returns a combined result.
func PerformComprehensiveAnalysis(rawURL string) models.URLAnalysisResult {
	urlFeatures := ExtractFeatures(rawURL)
	urlScore := EvaluateHeuristics(urlFeatures)

	htmlFeatures := FetchAndAnalyzeHTML(rawURL)

	finalScore := CalculateFinalScore(urlScore, htmlFeatures.HTMLScore)

	return models.URLAnalysisResult{
		URL:         rawURL,
		Score:       urlScore,
		URLDetails:  urlFeatures,
		HTMLDetails: convertHTMLFeatures(htmlFeatures),
		FinalScore:  finalScore,
	}
}

// CalculateFinalScore combines URL and HTML scores into a bounded final score.
func CalculateFinalScore(urlScore, htmlScore int) int {
	finalScore := int(float64(urlScore)*0.4 + float64(htmlScore)*0.6)

	if finalScore > 100 {
		finalScore = 100
	}

	return finalScore
}

func convertHTMLFeatures(internal HTMLFeatures) models.HTMLFeatures {
	return models.HTMLFeatures{
		ContentFetched:       internal.ContentFetched,
		HasSuspiciousTitle:   internal.HasSuspiciousTitle,
		HasPhishingKeywords:  internal.HasPhishingKeywords,
		HasSuspiciousForms:   internal.HasSuspiciousForms,
		HasExternalRedirects: internal.HasExternalRedirects,
		HasObfuscatedCode:    internal.HasObfuscatedCode,
		MissingSSLIndicators: internal.MissingSSLIndicators,
		HTMLScore:            internal.HTMLScore,
	}
}
