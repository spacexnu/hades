package analyzer

import (
	"context"
	"time"

	"hades/internal/db"
)

func approvedPhrases(category string, fallback []string) []string {
	pool := db.Pool()
	if pool == nil {
		return fallback
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	phrases, err := db.FetchApprovedPhrases(ctx, category)
	if err != nil || len(phrases) == 0 {
		return fallback
	}

	return phrases
}

func queuePendingPhrases(category string, phrases []string) {
	pool := db.Pool()
	if pool == nil || len(phrases) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := db.InsertPendingPhrases(ctx, phrases, category); err != nil {
		return
	}
}
