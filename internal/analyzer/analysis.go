// Package analyzer provides URL analysis functionality including feature extraction and heuristic evaluation.
package analyzer

import (
	"context"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"hades/internal/db"
	"hades/internal/models"
)

var suspiciousWordsEN = []string{
	"login",
	"verify",
	"update",
	"secure",
	"bank",
}

var suspiciousWordsPT = []string{
	"pagmei",
	"regulariza",
	"regularize",
	"imediato",
	"pagamento",
	"boleto",
	"pix",
	"cnpj",
	"cpf",
}

// ExtractFeatures parses a raw URL and produces URLFeatures populated with heuristic inputs.
func ExtractFeatures(rawURL string) models.URLFeatures {
	parsed, _ := url.Parse(rawURL)
	domain := parsed.Hostname()
	age := GetDomainAgeDays(domain)

	return models.URLFeatures{
		DomainLength:         len(domain),
		URLLength:            len(rawURL),
		HasSuspiciousWords:   containsSuspiciousWord(rawURL),
		HasLongNumericPath:   hasLongNumericPath(parsed.Path),
		InFeedBlocklist:      false,
		FeedMatchType:        "",
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
	if f.HasLongNumericPath {
		score += 20
	}
	if f.NumSubdomains > 3 {
		score += 5
	}
	if f.DomainLength >= 30 {
		score += 10
	}
	if f.InFeedBlocklist {
		score += 200
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
	keywords := approvedPhrases("url_keyword", append(suspiciousWordsEN, suspiciousWordsPT...))
	for _, k := range keywords {
		if strings.Contains(strings.ToLower(u), k) {
			return true
		}
	}
	return false
}

func hasLongNumericPath(path string) bool {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return false
	}

	segments := strings.Split(trimmed, "/")
	for _, segment := range segments {
		if len(segment) >= 10 && isAllDigits(segment) {
			return true
		}
	}
	return false
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
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
	feedMatch := lookupFeedMatch(rawURL)
	if feedMatch != "" {
		urlFeatures.InFeedBlocklist = true
		urlFeatures.FeedMatchType = feedMatch
	}
	urlScore := EvaluateHeuristics(urlFeatures)

	htmlFeatures := FetchAndAnalyzeHTML(rawURL)

	finalScore := CalculateFinalScore(urlScore, htmlFeatures.HTMLScore)

	if finalScore > 0 {
		queuePendingPhrases("url_keyword", extractCandidateTokens(rawURL))
	}

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

func lookupFeedMatch(rawURL string) string {
	pool := db.Pool()
	if pool == nil {
		return ""
	}

	normalizedURL := normalizeURLForLookup(rawURL)
	domainCandidates := extractDomainCandidates(rawURL)
	if normalizedURL == "" && len(domainCandidates) == 0 {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	matchType, err := db.FindFeedMatch(ctx, normalizedURL, domainCandidates)
	if err != nil {
		return ""
	}

	return matchType
}

func normalizeURLForLookup(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	parsed.Fragment = ""
	parsed.Host = strings.ToLower(parsed.Host)
	if parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.String()
}

func extractDomainCandidates(rawURL string) []string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return nil
	}
	if isIPAddress(host) {
		return []string{host}
	}

	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return []string{host}
	}

	var candidates []string
	for i := 0; i <= len(parts)-2; i++ {
		candidates = append(candidates, strings.Join(parts[i:], "."))
	}
	return candidates
}

func extractCandidateTokens(rawURL string) []string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	parts := []string{parsed.Hostname(), parsed.Path}
	tokenizer := regexp.MustCompile(`[^a-zA-Z0-9]+`)
	ignore := map[string]struct{}{
		"http":  {},
		"https": {},
		"www":   {},
		"com":   {},
		"net":   {},
		"org":   {},
		"br":    {},
	}

	seen := make(map[string]struct{})
	var tokens []string
	for _, part := range parts {
		for _, token := range tokenizer.Split(part, -1) {
			if token == "" {
				continue
			}
			token = strings.ToLower(token)
			if len(token) < 4 || len(token) > 32 {
				continue
			}
			if _, blocked := ignore[token]; blocked {
				continue
			}
			if isAllDigits(token) {
				continue
			}
			if _, exists := seen[token]; exists {
				continue
			}
			seen[token] = struct{}{}
			tokens = append(tokens, token)
		}
	}

	return tokens
}
