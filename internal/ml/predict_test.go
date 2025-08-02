package ml

import (
	"testing"

	"hades/internal/models"
)

func TestPredict(t *testing.T) {
	tests := []struct {
		name     string
		features models.URLFeatures
		expected float64
	}{
		{
			name: "basic features",
			features: models.URLFeatures{
				DomainLength:         15,
				URLLength:            50,
				HasSuspiciousWords:   true,
				NumSubdomains:        2,
				UsesIPAddress:        false,
				UsesInsecureProtocol: true,
				DomainAgeDays:        365,
			},
			expected: 0.0,
		},
		{
			name: "minimal features",
			features: models.URLFeatures{
				DomainLength:         5,
				URLLength:            10,
				HasSuspiciousWords:   false,
				NumSubdomains:        0,
				UsesIPAddress:        false,
				UsesInsecureProtocol: false,
				DomainAgeDays:        1000,
			},
			expected: 0.0,
		},
		{
			name: "suspicious features",
			features: models.URLFeatures{
				DomainLength:         30,
				URLLength:            100,
				HasSuspiciousWords:   true,
				NumSubdomains:        5,
				UsesIPAddress:        true,
				UsesInsecureProtocol: true,
				DomainAgeDays:        1,
			},
			expected: 0.0,
		},
		{
			name: "zero values",
			features: models.URLFeatures{
				DomainLength:         0,
				URLLength:            0,
				HasSuspiciousWords:   false,
				NumSubdomains:        0,
				UsesIPAddress:        false,
				UsesInsecureProtocol: false,
				DomainAgeDays:        0,
			},
			expected: 0.0,
		},
		{
			name: "negative domain age",
			features: models.URLFeatures{
				DomainLength:         10,
				URLLength:            25,
				HasSuspiciousWords:   false,
				NumSubdomains:        1,
				UsesIPAddress:        false,
				UsesInsecureProtocol: false,
				DomainAgeDays:        -1,
			},
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Predict(tt.features)
			if result != tt.expected {
				t.Errorf("Expected %f, got %f", tt.expected, result)
			}
		})
	}
}

func TestPredict_ReturnType(t *testing.T) {
	features := models.URLFeatures{}
	result := Predict(features)

	// Verify the function returns a float64
	if _, ok := interface{}(result).(float64); !ok {
		t.Errorf("Expected Predict to return float64, got %T", result)
	}
}

// Benchmark test for performance measurement
func BenchmarkPredict(b *testing.B) {
	features := models.URLFeatures{
		DomainLength:         15,
		URLLength:            50,
		HasSuspiciousWords:   true,
		NumSubdomains:        2,
		UsesIPAddress:        false,
		UsesInsecureProtocol: true,
		DomainAgeDays:        365,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Predict(features)
	}
}
