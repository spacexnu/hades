package main

import (
	"context"
	"flag"
	"log"
	"os"
	"time"

	"hades/internal/db"
	"hades/internal/ingest"
)

func main() {
	databaseURL := flag.String("database", "", "Database connection string")
	interval := flag.Duration("interval", 0, "Ingest interval (e.g. 6h). 0 runs once")
	flag.Parse()

	connStr := *databaseURL
	if connStr == "" {
		connStr = os.Getenv("DATABASE_URL")
	}
	if connStr == "" {
		log.Fatal("DATABASE_URL is required")
	}

	if *interval == 0 {
		if envInterval := os.Getenv("INGEST_INTERVAL"); envInterval != "" {
			parsed, err := time.ParseDuration(envInterval)
			if err != nil {
				log.Fatalf("invalid INGEST_INTERVAL: %v", err)
			}
			*interval = parsed
		}
	}

	if err := db.Connect(connStr); err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer db.Close()

	runOnce := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		if err := ingest.Run(ctx); err != nil {
			log.Printf("ingest failed: %v", err)
		} else {
			log.Printf("ingest completed")
		}
	}

	if *interval <= 0 {
		runOnce()
		return
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	for {
		runOnce()
		<-ticker.C
	}
}
