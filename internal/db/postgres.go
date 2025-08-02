// Package db provides PostgreSQL database connection and management functionality.
package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

var pool *pgxpool.Pool

// Connect establishes a connection to the PostgreSQL database using the provided connection string.
func Connect(connStr string) error {
	var err error
	pool, err = pgxpool.New(context.Background(), connStr)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	return pool.Ping(context.Background())
}

// Close closes the database connection pool if it exists.
func Close() {
	if pool != nil {
		pool.Close()
	}
}

// Pool returns the current database connection pool.
func Pool() *pgxpool.Pool {
	return pool
}
