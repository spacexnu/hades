package analyzer

import (
	"testing"

	"hades/internal/models"
)

func TestExtractFeatures(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected models.URLFeatures
	}{
		{
			name: "simple HTTPS URL",
			url:  "https://example.com",
			expected: models.URLFeatures{
				DomainLength:         11, // "example.com"
				URLLength:            19, // "https://example.com"
				HasSuspiciousWords:   false,
				NumSubdomains:        0, // example.com has 2 parts, so 2-2=0 subdomains
				UsesIPAddress:        false,
				UsesInsecureProtocol: false,
				DomainAgeDays:        10951, // Actual domain age from WHOIS lookup
			},
		},
		{
			name: "HTTP URL with suspicious word",
			url:  "http://login.example.com/verify",
			expected: models.URLFeatures{
				DomainLength:         17,   // "login.example.com"
				URLLength:            31,   // "http://login.example.com/verify"
				HasSuspiciousWords:   true, // contains "login" and "verify"
				NumSubdomains:        1,    // login.example.com has 3 parts, so 3-2=1 subdomain
				UsesIPAddress:        false,
				UsesInsecureProtocol: true,
				DomainAgeDays:        -1, // WHOIS lookup fails for subdomains
			},
		},
		{
			name: "URL with multiple subdomains",
			url:  "https://sub1.sub2.sub3.example.com",
			expected: models.URLFeatures{
				DomainLength:         26, // "sub1.sub2.sub3.example.com"
				URLLength:            34, // "https://sub1.sub2.sub3.example.com"
				HasSuspiciousWords:   false,
				NumSubdomains:        3, // sub1.sub2.sub3.example.com has 5 parts, so 5-2=3 subdomains
				UsesIPAddress:        false,
				UsesInsecureProtocol: false,
				DomainAgeDays:        -1, // This domain likely doesn't exist, so WHOIS will fail
			},
		},
		{
			name: "URL with bank keyword",
			url:  "https://secure-bank-login.com",
			expected: models.URLFeatures{
				DomainLength:         21,   // "secure-bank-login.com"
				URLLength:            29,   // "https://secure-bank-login.com"
				HasSuspiciousWords:   true, // contains "bank" and "login"
				NumSubdomains:        0,    // secure-bank-login.com has 2 parts, so 2-2=0 subdomains
				UsesIPAddress:        false,
				UsesInsecureProtocol: false,
				DomainAgeDays:        -1,
			},
		},
		{
			name: "URL with update keyword",
			url:  "http://update.example.org/secure",
			expected: models.URLFeatures{
				DomainLength:         18,   // "update.example.org"
				URLLength:            32,   // "http://update.example.org/secure"
				HasSuspiciousWords:   true, // contains "update" and "secure"
				NumSubdomains:        1,    // update.example.org has 3 parts, so 3-2=1 subdomain
				UsesIPAddress:        false,
				UsesInsecureProtocol: true,
				DomainAgeDays:        -1, // This subdomain likely doesn't exist, so WHOIS will fail
			},
		},
		{
			name: "URL with IPv4 address",
			url:  "http://192.168.1.1/login",
			expected: models.URLFeatures{
				DomainLength:         11,   // "192.168.1.1"
				URLLength:            24,   // "http://192.168.1.1/login"
				HasSuspiciousWords:   true, // contains "login"
				NumSubdomains:        2,    // IP addresses are split by dots: 4 parts - 2 = 2
				UsesIPAddress:        true,
				UsesInsecureProtocol: true,
				DomainAgeDays:        -1, // IP addresses don't have WHOIS data
			},
		},
		{
			name: "URL with IPv6 address",
			url:  "https://[2001:db8::1]/secure",
			expected: models.URLFeatures{
				DomainLength:         11,   // "2001:db8::1"
				URLLength:            28,   // "https://[2001:db8::1]/secure"
				HasSuspiciousWords:   true, // contains "secure"
				NumSubdomains:        -1,   // IPv6 has no dots: 1 part - 2 = -1
				UsesIPAddress:        true,
				UsesInsecureProtocol: false,
				DomainAgeDays:        -1, // IP addresses don't have WHOIS data
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractFeatures(tt.url)

			if result.DomainLength != tt.expected.DomainLength {
				t.Errorf("DomainLength: expected %d, got %d", tt.expected.DomainLength, result.DomainLength)
			}
			if result.URLLength != tt.expected.URLLength {
				t.Errorf("URLLength: expected %d, got %d", tt.expected.URLLength, result.URLLength)
			}
			if result.HasSuspiciousWords != tt.expected.HasSuspiciousWords {
				t.Errorf("HasSuspiciousWords: expected %t, got %t", tt.expected.HasSuspiciousWords, result.HasSuspiciousWords)
			}
			if result.NumSubdomains != tt.expected.NumSubdomains {
				t.Errorf("NumSubdomains: expected %d, got %d", tt.expected.NumSubdomains, result.NumSubdomains)
			}
			if result.UsesIPAddress != tt.expected.UsesIPAddress {
				t.Errorf("UsesIPAddress: expected %t, got %t", tt.expected.UsesIPAddress, result.UsesIPAddress)
			}
			if result.UsesInsecureProtocol != tt.expected.UsesInsecureProtocol {
				t.Errorf("UsesInsecureProtocol: expected %t, got %t", tt.expected.UsesInsecureProtocol, result.UsesInsecureProtocol)
			}
			// Note: DomainAgeDays will likely be -1 in tests due to WHOIS lookup failures
			if result.DomainAgeDays != tt.expected.DomainAgeDays {
				t.Errorf("DomainAgeDays: expected %d, got %d", tt.expected.DomainAgeDays, result.DomainAgeDays)
			}
		})
	}
}

func TestEvaluateHeuristics(t *testing.T) {
	tests := []struct {
		name     string
		features models.URLFeatures
		expected int
	}{
		{
			name: "no suspicious features",
			features: models.URLFeatures{
				DomainLength:         15,
				URLLength:            30,
				HasSuspiciousWords:   false,
				NumSubdomains:        1,
				UsesIPAddress:        false,
				UsesInsecureProtocol: false,
				DomainAgeDays:        365,
			},
			expected: 0,
		},
		{
			name: "insecure protocol only",
			features: models.URLFeatures{
				DomainLength:         15,
				URLLength:            30,
				HasSuspiciousWords:   false,
				NumSubdomains:        1,
				UsesIPAddress:        false,
				UsesInsecureProtocol: true,
				DomainAgeDays:        365,
			},
			expected: 10,
		},
		{
			name: "suspicious words only",
			features: models.URLFeatures{
				DomainLength:         15,
				URLLength:            30,
				HasSuspiciousWords:   true,
				NumSubdomains:        1,
				UsesIPAddress:        false,
				UsesInsecureProtocol: false,
				DomainAgeDays:        365,
			},
			expected: 20,
		},
		{
			name: "many subdomains only",
			features: models.URLFeatures{
				DomainLength:         15,
				URLLength:            30,
				HasSuspiciousWords:   false,
				NumSubdomains:        4,
				UsesIPAddress:        false,
				UsesInsecureProtocol: false,
				DomainAgeDays:        365,
			},
			expected: 5,
		},
		{
			name: "IP address only",
			features: models.URLFeatures{
				DomainLength:         15,
				URLLength:            30,
				HasSuspiciousWords:   false,
				NumSubdomains:        0,
				UsesIPAddress:        true,
				UsesInsecureProtocol: false,
				DomainAgeDays:        365,
			},
			expected: 25,
		},
		{
			name: "new domain only",
			features: models.URLFeatures{
				DomainLength:         15,
				URLLength:            30,
				HasSuspiciousWords:   false,
				NumSubdomains:        1,
				UsesIPAddress:        false,
				UsesInsecureProtocol: false,
				DomainAgeDays:        15,
			},
			expected: 50,
		},
		{
			name: "all suspicious features",
			features: models.URLFeatures{
				DomainLength:         15,
				URLLength:            30,
				HasSuspiciousWords:   true,
				NumSubdomains:        5,
				UsesIPAddress:        true,
				UsesInsecureProtocol: true,
				DomainAgeDays:        5,
			},
			expected: 110, // 10 + 20 + 5 + 25 + 50
		},
		{
			name: "domain age exactly 30 days",
			features: models.URLFeatures{
				DomainLength:         15,
				URLLength:            30,
				HasSuspiciousWords:   false,
				NumSubdomains:        1,
				UsesIPAddress:        false,
				UsesInsecureProtocol: false,
				DomainAgeDays:        30,
			},
			expected: 0, // 30 days is not < 30, so no penalty
		},
		{
			name: "domain age -1 (error case)",
			features: models.URLFeatures{
				DomainLength:         15,
				URLLength:            30,
				HasSuspiciousWords:   false,
				NumSubdomains:        1,
				UsesIPAddress:        false,
				UsesInsecureProtocol: false,
				DomainAgeDays:        -1,
			},
			expected: 0, // -1 is not >= 0, so no penalty
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EvaluateHeuristics(tt.features)
			if result != tt.expected {
				t.Errorf("Expected score %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestContainsSuspiciousWord(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{
			name:     "no suspicious words",
			url:      "https://example.com",
			expected: false,
		},
		{
			name:     "contains login",
			url:      "https://login.example.com",
			expected: true,
		},
		{
			name:     "contains verify",
			url:      "https://example.com/verify",
			expected: true,
		},
		{
			name:     "contains update",
			url:      "https://update.example.com",
			expected: true,
		},
		{
			name:     "contains secure",
			url:      "https://secure.example.com",
			expected: true,
		},
		{
			name:     "contains bank",
			url:      "https://bank.example.com",
			expected: true,
		},
		{
			name:     "contains multiple suspicious words",
			url:      "https://secure-bank-login.com/verify",
			expected: true,
		},
		{
			name:     "case insensitive - LOGIN",
			url:      "https://LOGIN.example.com",
			expected: true,
		},
		{
			name:     "case insensitive - BANK",
			url:      "https://BANK.example.com",
			expected: true,
		},
		{
			name:     "partial word match - blogin",
			url:      "https://blogin.example.com",
			expected: true, // contains "login"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsSuspiciousWord(tt.url)
			if result != tt.expected {
				t.Errorf("Expected %t, got %t", tt.expected, result)
			}
		})
	}
}

func TestIsIPAddress(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{
			name:     "regular domain",
			host:     "example.com",
			expected: false,
		},
		{
			name:     "IPv4 address",
			host:     "192.168.1.1",
			expected: true,
		},
		{
			name:     "IPv6 address",
			host:     "2001:db8::1",
			expected: true,
		},
		{
			name:     "IPv6 full address",
			host:     "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			expected: true,
		},
		{
			name:     "IPv6 loopback",
			host:     "::1",
			expected: true,
		},
		{
			name:     "IPv4 loopback",
			host:     "127.0.0.1",
			expected: true,
		},
		{
			name:     "IPv4 public address",
			host:     "8.8.8.8",
			expected: true,
		},
		{
			name:     "IPv4 with port (invalid)",
			host:     "192.168.1.1:8080",
			expected: false,
		},
		{
			name:     "localhost",
			host:     "localhost",
			expected: false,
		},
		{
			name:     "domain with numbers",
			host:     "test123.com",
			expected: false,
		},
		{
			name:     "invalid IPv4 (too many octets)",
			host:     "192.168.1.1.1",
			expected: false,
		},
		{
			name:     "invalid IPv4 (octet too large)",
			host:     "192.168.256.1",
			expected: false,
		},
		{
			name:     "invalid IPv6",
			host:     "2001:db8::1::2",
			expected: false,
		},
		{
			name:     "empty string",
			host:     "",
			expected: false,
		},
		{
			name:     "subdomain",
			host:     "sub.example.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isIPAddress(tt.host)
			if result != tt.expected {
				t.Errorf("Expected %t, got %t", tt.expected, result)
			}
		})
	}
}

// Benchmark tests
func BenchmarkExtractFeatures(b *testing.B) {
	url := "https://secure-login.example.com/verify"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractFeatures(url)
	}
}

func BenchmarkEvaluateHeuristics(b *testing.B) {
	features := models.URLFeatures{
		DomainLength:         15,
		URLLength:            30,
		HasSuspiciousWords:   true,
		NumSubdomains:        3,
		UsesIPAddress:        false,
		UsesInsecureProtocol: true,
		DomainAgeDays:        15,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EvaluateHeuristics(features)
	}
}

func BenchmarkContainsSuspiciousWord(b *testing.B) {
	url := "https://secure-bank-login.example.com/verify"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		containsSuspiciousWord(url)
	}
}
