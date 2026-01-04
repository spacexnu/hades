run:
	go run ./cmd/server

build:
	go build -o hades ./cmd/server

lint:
	golangci-lint run ./...

# Migration configuration
MIGRATE_PATH ?= ./migrations
MIGRATE_DB ?= postgres://hades:hades@localhost:5432/hades?sslmode=disable
DATABASE_URL ?= postgres://hades:hades@localhost:5432/hades?sslmode=disable

# Test targets
test:
	go test ./...

test-verbose:
	go test -v ./...

test-coverage:
	go test -cover ./...

test-coverage-html:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-models:
	go test -v ./internal/models

test-analyzer:
	go test -v ./internal/analyzer

test-api:
	go test -v ./internal/api

test-db:
	go test -v ./internal/db

test-ml:
	go test -v ./internal/ml

test-fast:
	go test -short ./...

benchmark:
	go test -bench=. ./...

clean-test:
	rm -f coverage.out coverage.html


migrate-up:
	migrate -path $(MIGRATE_PATH) -database "$(MIGRATE_DB)" up

migrate-down:
	migrate -path $(MIGRATE_PATH) -database "$(MIGRATE_DB)" down

migrate:
	migrate -path $(MIGRATE_PATH) -database "$(MIGRATE_DB)" up

ingest:
	DATABASE_URL="$(DATABASE_URL)" go run ./cmd/ingest

ingest-loop:
	DATABASE_URL="$(DATABASE_URL)" go run ./cmd/ingest -interval 6h

docker-build:
	docker build -t hades:latest .

docker-up:
	docker-compose up --build -d

docker-test:
	docker compose run --rm hades-test

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

docker-clean:
	docker-compose down -v --remove-orphans
	docker rmi hades:latest || true

docker-psql:
	docker exec -it hades-db psql -U hades -d hades

docker-migrate-up:
	docker run --rm \
		--network hades_default \
		-v $(PWD)/migrations:/migrations \
		migrate/migrate \
		-path=/migrations \
		-database postgres://hades:hades@db:5432/hades?sslmode=disable up

docker-migrate-down:
	docker run --rm \
		--network hades_default \
		-v $(PWD)/migrations:/migrations \
		migrate/migrate \
		-path=/migrations \
		-database postgres://hades:hades@db:5432/hades?sslmode=disable down

.PHONY: run build test test-verbose test-coverage test-coverage-html test-models test-analyzer test-api test-db test-ml test-fast benchmark clean-test migrate migrate-up migrate-down ingest ingest-loop docker-build docker-up docker-test docker-down docker-logs docker-clean
