# HADES

[![Go Report Card](https://goreportcard.com/badge/github.com/spacexnu/hades)](https://goreportcard.com/report/github.com/spacexnu/hades)
[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/spacexnu/hades/pulls)


**H**euristic **A**nalysis of **D**omains & **E**mbedded **S**ites

HADES is an open-source service written in Go to analyze URLs and detect potential fraud, scams, and phishing attempts.  
It uses simple yet effective heuristics to evaluate URLs without relying on restrictive or paid external services.

---

## Features

- **Analyze multiple URLs** via REST API (`/analyze`)
- **Heuristics applied:**
    - Insecure protocol (`http://` instead of `https://`)
    - Suspicious keywords in URL (`login`, `verify`, `secure`, `bank`, `update`)
    - IP address instead of hostname
    - Excessive subdomain count
    - **Domain age** (via WHOIS lookup)

### Scoring System

HADES uses a numeric score to indicate potential risk. Higher scores mean higher risk:
- 0 → No detected risk
- 1-50 → Low risk
- 51-100 → Medium risk
- >100 → High risk

The score is calculated by applying weighted penalties for suspicious URL characteristics such as insecure protocols, suspicious keywords, excessive subdomains, IP addresses instead of hostnames, and recently registered domains.

- **JSON response** with score and extracted feature details
- **Future-ready architecture** for Machine Learning (ONNX inference)

---

## Roadmap

### MVP (current)
- REST API
- URL feature extraction
- Heuristic-based scoring
- Domain age via WHOIS

### Next steps
- Local WHOIS caching (SQLite)
- Basic HTML parsing (detecting malicious forms)
- Dynamic configuration for suspicious keywords
- Parallel processing (goroutines)
- Optional ML integration (ONNX)

---

## Getting started

### Requirements
- Go 1.21 or newer

### Run locally
```bash
git clone https://github.com/YOUR_USERNAME/hades.git
cd hades
go mod tidy
go run ./cmd/server
```

### API usage

## Endpoint

#### POST /analyze

#### Request body
```json
{
  "urls": [
    "http://example.com/login",
    "https://google.com"
  ]
}
```

#### Response body
```json
[
  {
    "url": "http://example.com/login",
    "score": 80,
    "details": {
      "domain_length": 11,
      "url_length": 28,
      "has_suspicious_words": true,
      "num_subdomains": 0,
      "uses_ip_address": false,
      "uses_insecure_protocol": true,
      "domain_age_days": 12
    }
  },
  {
    "url": "https://google.com",
    "score": 0,
    "details": {
      "domain_length": 10,
      "url_length": 18,
      "has_suspicious_words": false,
      "num_subdomains": 0,
      "uses_ip_address": false,
      "uses_insecure_protocol": false,
      "domain_age_days": 9000
    }
  }
]
```

### Project Structure
```text
hades/
 ├── cmd/server/         # Application entry point
 ├── internal/api/       # HTTP handlers
 ├── internal/analyzer/  # Feature extraction & heuristic scoring
 ├── internal/ml/        # Placeholder for future ML inference
 ├── internal/models/    # Data structures (request/response)
 ├── go.mod
 ├── go.sum
 ├── Dockerfile
 ├── Makefile
 └── README.md
```
## Testing

HADES includes comprehensive unit tests for all major components. You can run tests using Go commands directly or the provided Makefile targets.

### Running Tests

#### All tests
```bash
# Run all tests
make test

# Run all tests with verbose output
make test-verbose

# Run tests with coverage report
make test-coverage

# Generate HTML coverage report
make test-coverage-html
```

#### Individual package tests
```bash
# Test specific packages
make test-models     # Test data models
make test-analyzer   # Test URL analysis logic
make test-api        # Test HTTP handlers
make test-db         # Test database operations
make test-ml         # Test ML prediction logic
```

#### Other test options
```bash
# Run fast tests (skip slow tests)
make test-fast

# Run benchmarks
make benchmark

# Clean up test artifacts
make clean-test
```

#### Using Go commands directly
```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/analyzer
go test ./internal/api

# Run with golangci-lint (aggregated linter)
golangci-lint run
```

### Linting

HADES uses [golangci-lint](https://golangci-lint.run/) for static code analysis.  
You can run it locally (after installing) or via Docker:

```bash
# Local execution
golangci-lint run
```

### Contributing

Pull requests are welcome.

Follow Go best practices (linters, unit tests, semantic commits).

### License

Distributed under the BSD 3-Clause License. See [LICENSE](LICENSE) for more information.
