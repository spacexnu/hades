package db

import (
	"testing"
)

func TestConnect_InvalidConnectionString(t *testing.T) {
	// Test with invalid connection string
	err := Connect("invalid-connection-string")
	if err == nil {
		t.Error("Expected error for invalid connection string, got nil")
	}

	// Clean up - ensure pool is nil after failed connection
	if pool != nil {
		pool.Close()
		pool = nil
	}
}

func TestConnect_EmptyConnectionString(t *testing.T) {
	// Test with empty connection string
	err := Connect("")
	if err == nil {
		t.Error("Expected error for empty connection string, got nil")
	}

	// Clean up
	if pool != nil {
		pool.Close()
		pool = nil
	}
}

func TestClose_WithNilPool(t *testing.T) {
	// Ensure pool is nil
	pool = nil

	// This should not panic
	Close()

	// Verify pool is still nil
	if pool != nil {
		t.Error("Expected pool to remain nil after Close() with nil pool")
	}
}

func TestPool_WithNilPool(t *testing.T) {
	// Ensure pool is nil
	pool = nil

	result := Pool()
	if result != nil {
		t.Error("Expected Pool() to return nil when pool is nil")
	}
}

func TestConnect_ErrorMessage(t *testing.T) {
	err := Connect("invalid://connection")
	if err == nil {
		t.Fatal("Expected error for invalid connection string")
	}

	// Check that error message contains expected text
	expectedText := "failed to connect to database"
	if !containsString(err.Error(), expectedText) {
		t.Errorf("Expected error message to contain '%s', got: %s", expectedText, err.Error())
	}

	// Clean up
	if pool != nil {
		pool.Close()
		pool = nil
	}
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Integration test - only runs if DATABASE_URL is set
func TestConnect_ValidConnection(t *testing.T) {
	// Skip this test in normal unit test runs
	// This would require a real database connection
	t.Skip("Skipping integration test - requires real database")

	// Example of how this test would work with a real database:
	// connStr := os.Getenv("TEST_DATABASE_URL")
	// if connStr == "" {
	//     t.Skip("TEST_DATABASE_URL not set, skipping integration test")
	// }
	//
	// err := Connect(connStr)
	// if err != nil {
	//     t.Fatalf("Failed to connect to test database: %v", err)
	// }
	//
	// // Test that Pool() returns non-nil
	// if Pool() == nil {
	//     t.Error("Expected Pool() to return non-nil after successful connection")
	// }
	//
	// // Test Close
	// Close()
	//
	// // After Close, pool should be nil or closed
	// // Note: We can't easily test this without accessing internal state
}

// Test concurrent access safety
func TestConcurrentAccess(t *testing.T) {
	// Ensure clean state
	pool = nil

	// Test that multiple goroutines calling Pool() don't cause race conditions
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()
			result := Pool()
			if result != nil {
				t.Error("Expected Pool() to return nil when no connection established")
			}
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestClose_MultipleCalls(t *testing.T) {
	// Ensure clean state
	pool = nil

	// Multiple calls to Close() should not panic
	Close()
	Close()
	Close()

	// Verify pool is still nil
	if pool != nil {
		t.Error("Expected pool to remain nil after multiple Close() calls")
	}
}

// Benchmark tests
func BenchmarkPool(b *testing.B) {
	// Ensure clean state
	pool = nil

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Pool()
	}
}

func BenchmarkClose(b *testing.B) {
	// Ensure clean state
	pool = nil

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Close()
	}
}
