package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// FeedSource represents an enabled feed source.
type FeedSource struct {
	ID       int
	Name     string
	URL      string
	Category string
}

// FeedEntry represents a normalized entry to store.
type FeedEntry struct {
	EntryType string
	Value     string
}

// FetchEnabledFeedSources returns enabled feed sources.
func FetchEnabledFeedSources(ctx context.Context) ([]FeedSource, error) {
	if pool == nil {
		return nil, nil
	}

	rows, err := pool.Query(ctx, `
		SELECT id, name, url, category
		FROM feed_sources
		WHERE enabled = TRUE
		ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("query feed_sources: %w", err)
	}
	defer rows.Close()

	var sources []FeedSource
	for rows.Next() {
		var src FeedSource
		if scanErr := rows.Scan(&src.ID, &src.Name, &src.URL, &src.Category); scanErr != nil {
			return nil, fmt.Errorf("scan feed_sources: %w", scanErr)
		}
		sources = append(sources, src)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("iterate feed_sources: %w", rows.Err())
	}

	return sources, nil
}

// InsertFeedEntries inserts feed entries for a source, ignoring duplicates.
func InsertFeedEntries(ctx context.Context, sourceID int, entries []FeedEntry) error {
	if pool == nil || len(entries) == 0 {
		return nil
	}

	entryTypes := make([]string, 0, len(entries))
	values := make([]string, 0, len(entries))
	for _, entry := range entries {
		entryTypes = append(entryTypes, entry.EntryType)
		values = append(values, entry.Value)
	}

	_, err := pool.Exec(ctx, `
		INSERT INTO feed_entries (source_id, entry_type, value)
		SELECT $1, t.entry_type, t.value
		FROM UNNEST($2::text[], $3::text[]) AS t(entry_type, value)
		ON CONFLICT DO NOTHING
	`, sourceID, entryTypes, values)
	if err != nil {
		return fmt.Errorf("insert feed_entries: %w", err)
	}

	return nil
}

// FindFeedMatch returns a matching entry type ("url" or "domain") when found.
func FindFeedMatch(ctx context.Context, normalizedURL string, domains []string) (string, error) {
	if pool == nil {
		return "", nil
	}

	if normalizedURL != "" {
		var entryType string
		err := pool.QueryRow(ctx, `
			SELECT entry_type
			FROM feed_entries
			WHERE entry_type = 'url' AND value = $1
			LIMIT 1
		`, normalizedURL).Scan(&entryType)
		if err == nil {
			return entryType, nil
		}
		if err != pgx.ErrNoRows {
			return "", fmt.Errorf("query feed_entries url: %w", err)
		}
	}

	if len(domains) == 0 {
		return "", nil
	}

	var entryType string
	err := pool.QueryRow(ctx, `
		SELECT entry_type
		FROM feed_entries
		WHERE entry_type = 'domain' AND value = ANY($1)
		LIMIT 1
	`, domains).Scan(&entryType)
	if err == nil {
		return entryType, nil
	}
	if err != pgx.ErrNoRows {
		return "", fmt.Errorf("query feed_entries domain: %w", err)
	}

	return "", nil
}
