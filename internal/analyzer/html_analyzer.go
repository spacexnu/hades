// Package analyzer provides HTML content analysis functionality for fraud detection.
package analyzer

import (
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// HTMLFeatures captures heuristic signals derived from parsed HTML used for phishing detection.
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

// FetchAndAnalyzeHTML downloads the URL's HTML and computes HTMLFeatures; on failure returns defaults.
func FetchAndAnalyzeHTML(url string) HTMLFeatures {
	features := HTMLFeatures{
		ContentFetched: false,
		HTMLScore:      0,
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return features
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Printf("error closing response body: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return features
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return features
	}

	htmlContent := string(body)
	features.ContentFetched = true

	features.HasSuspiciousTitle = analyzeSuspiciousTitle(htmlContent)
	features.HasPhishingKeywords = analyzePhishingKeywords(htmlContent)
	features.HasSuspiciousForms = analyzeSuspiciousForms(htmlContent)
	features.HasExternalRedirects = analyzeExternalRedirects(htmlContent)
	features.HasObfuscatedCode = analyzeObfuscatedCode(htmlContent)
	features.MissingSSLIndicators = analyzeMissingSSLIndicators(htmlContent)

	features.HTMLScore = calculateHTMLScore(features)

	return features
}

func analyzeSuspiciousTitle(html string) bool {
	suspiciousTitles := []string{
		"verify your account",
		"account suspended",
		"urgent action required",
		"security alert",
		"confirm your identity",
		"update payment",
		"expired session",
		"login verification",
	}

	titleRegex := regexp.MustCompile(`<title[^>]*>(.*?)</title>`)
	matches := titleRegex.FindStringSubmatch(html)
	if len(matches) < 2 {
		return false
	}

	title := strings.ToLower(matches[1])
	for _, suspicious := range suspiciousTitles {
		if strings.Contains(title, suspicious) {
			return true
		}
	}
	return false
}

func analyzePhishingKeywords(html string) bool {
	phishingKeywords := []string{
		"click here to verify",
		"account will be closed",
		"immediate action required",
		"suspended account",
		"confirm your password",
		"update your information",
		"verify identity",
		"security breach",
		"unauthorized access",
		"click here immediately",
	}

	htmlLower := strings.ToLower(html)
	for _, keyword := range phishingKeywords {
		if strings.Contains(htmlLower, keyword) {
			return true
		}
	}
	return false
}

func analyzeSuspiciousForms(html string) bool {
	passwordFormRegex := regexp.MustCompile(`<form[^>]*>.*?<input[^>]*type=["']password["'][^>]*>.*?</form>`)
	if passwordFormRegex.MatchString(html) {
		suspiciousActions := []string{
			"login",
			"signin",
			"verify",
			"confirm",
			"update",
			"secure",
		}

		actionRegex := regexp.MustCompile(`action=["']([^"']+)["']`)
		matches := actionRegex.FindAllStringSubmatch(html, -1)
		for _, match := range matches {
			if len(match) > 1 {
				action := strings.ToLower(match[1])
				for _, suspicious := range suspiciousActions {
					if strings.Contains(action, suspicious) {
						return true
					}
				}
			}
		}
	}
	return false
}

func analyzeExternalRedirects(html string) bool {
	metaRefreshRegex := regexp.MustCompile(`<meta[^>]*http-equiv=["']refresh["'][^>]*content=["'][^"']*url=([^"']+)["']`)
	matches := metaRefreshRegex.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) > 1 {
			url := match[1]
			if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
				return true
			}
		}
	}

	jsRedirectPatterns := []string{
		`window\.location\.href\s*=\s*["'][^"']*http`,
		`window\.location\s*=\s*["'][^"']*http`,
		`location\.href\s*=\s*["'][^"']*http`,
	}

	for _, pattern := range jsRedirectPatterns {
		regex := regexp.MustCompile(pattern)
		if regex.MatchString(html) {
			return true
		}
	}

	return false
}

func analyzeObfuscatedCode(html string) bool {
	obfuscationPatterns := []string{
		`eval\s*\(`,
		`document\.write\s*\(\s*unescape`,
		`String\.fromCharCode`,
		`\\x[0-9a-fA-F]{2}`,
		`\\u[0-9a-fA-F]{4}`,
		`atob\s*\(`,
		`btoa\s*\(`,
	}

	for _, pattern := range obfuscationPatterns {
		regex := regexp.MustCompile(pattern)
		if regex.MatchString(html) {
			return true
		}
	}
	return false
}

func analyzeMissingSSLIndicators(html string) bool {
	insecurePatterns := []string{
		`src=["']http://`,
		`href=["']http://`,
		`action=["']http://`,
	}

	for _, pattern := range insecurePatterns {
		regex := regexp.MustCompile(pattern)
		if regex.MatchString(html) {
			return true
		}
	}
	return false
}

func calculateHTMLScore(features HTMLFeatures) int {
	score := 0

	if !features.ContentFetched {
		return 30 // Penalty for not being able to fetch content
	}

	if features.HasSuspiciousTitle {
		score += 25
	}
	if features.HasPhishingKeywords {
		score += 30
	}
	if features.HasSuspiciousForms {
		score += 35
	}
	if features.HasExternalRedirects {
		score += 20
	}
	if features.HasObfuscatedCode {
		score += 40
	}
	if features.MissingSSLIndicators {
		score += 15
	}

	return score
}
