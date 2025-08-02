// Package analyzer provides URL analysis functionality including feature extraction and heuristic evaluation.
package analyzer

import (
	"net"
	"net/url"
	"strings"

	"hades/internal/models"
)

// ExtractFeatures extracts security-relevant features from a URL for analysis.
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

// EvaluateHeuristics calculates a risk score based on URL features using heuristic rules.
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
