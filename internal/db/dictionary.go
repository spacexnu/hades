package db

import (
	"context"
	"fmt"
)

// FetchApprovedPhrases returns approved phrases for the provided category.
func FetchApprovedPhrases(ctx context.Context, category string) ([]string, error) {
	if pool == nil {
		return nil, nil
	}

	rows, err := pool.Query(ctx, `
		SELECT phrase
		FROM suspicious_dictionary
		WHERE category = $1 AND status = 'approved'
	`, category)
	if err != nil {
		return nil, fmt.Errorf("query suspicious_dictionary: %w", err)
	}
	defer rows.Close()

	var phrases []string
	for rows.Next() {
		var phrase string
		if scanErr := rows.Scan(&phrase); scanErr != nil {
			return nil, fmt.Errorf("scan suspicious_dictionary: %w", scanErr)
		}
		phrases = append(phrases, phrase)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("iterate suspicious_dictionary: %w", rows.Err())
	}

	return phrases, nil
}

// InsertPendingPhrases queues phrases for moderation under the provided category.
func InsertPendingPhrases(ctx context.Context, phrases []string, category string) error {
	if pool == nil || len(phrases) == 0 {
		return nil
	}

	_, err := pool.Exec(ctx, `
		INSERT INTO suspicious_dictionary (phrase, language, category, status, source)
		SELECT UNNEST($1::text[]), 'unknown', $2, 'awaiting_moderation', 'auto'
		ON CONFLICT DO NOTHING
	`, phrases, category)
	if err != nil {
		return fmt.Errorf("insert pending phrases: %w", err)
	}

	return nil
}
