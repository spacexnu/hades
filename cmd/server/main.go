// Package main provides the HTTP server entry point for the HADES URL analysis service.
package main

import (
	"log"
	"net/http"
	"os"

	"hades/internal/api"
	"hades/internal/db"
)

func main() {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		log.Fatal("DATABASE_URL not set")
	}
	if err := db.Connect(connStr); err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/analyze", api.AnalyzeHandler)
	mux.HandleFunc("/health", api.HealthHandler)

	log.Println("[HADES] Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
