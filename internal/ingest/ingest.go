package ingest

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"hades/internal/db"
)

const (
	entryTypeDomain = "domain"
	entryTypeURL    = "url"
)

// Run fetches enabled feeds and inserts parsed entries.
func Run(ctx context.Context) error {
	sources, err := db.FetchEnabledFeedSources(ctx)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 20 * time.Second}
	for _, source := range sources {
		if err := ingestSource(ctx, client, source); err != nil {
			return fmt.Errorf("ingest %s: %w", source.Name, err)
		}
	}

	return nil
}

func ingestSource(ctx context.Context, client *http.Client, source db.FeedSource) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %s", resp.Status)
	}

	entries := make([]db.FeedEntry, 0, 2048)
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		entryType, value, ok := parseLine(scanner.Text())
		if !ok {
			continue
		}
		key := entryType + ":" + value
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		entries = append(entries, db.FeedEntry{EntryType: entryType, Value: value})
		if len(entries) >= 2000 {
			if err := db.InsertFeedEntries(ctx, source.ID, entries); err != nil {
				return err
			}
			entries = entries[:0]
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	if len(entries) > 0 {
		if err := db.InsertFeedEntries(ctx, source.ID, entries); err != nil {
			return err
		}
	}

	return nil
}

func parseLine(line string) (string, string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", "", false
	}
	if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "!") {
		return "", "", false
	}

	if strings.HasPrefix(trimmed, "0.0.0.0 ") || strings.HasPrefix(trimmed, "127.0.0.1 ") {
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			return "", "", false
		}
		return normalizeDomainEntry(fields[len(fields)-1])
	}

	if strings.HasPrefix(trimmed, "||") {
		domain := strings.TrimPrefix(trimmed, "||")
		domain = cutAtDelims(domain, "^/\\")
		return normalizeDomainEntry(domain)
	}

	if strings.HasPrefix(trimmed, "|http://") || strings.HasPrefix(trimmed, "|https://") {
		trimmed = strings.TrimPrefix(trimmed, "|")
	}

	if strings.Contains(trimmed, "://") {
		value := normalizeURL(trimmed)
		if value == "" {
			return "", "", false
		}
		return entryTypeURL, value, true
	}

	if strings.Contains(trimmed, ".") {
		return normalizeDomainEntry(trimmed)
	}

	return "", "", false
}

func normalizeDomainEntry(raw string) (string, string, bool) {
	normalized := normalizeDomain(raw)
	if normalized == "" {
		return "", "", false
	}
	return entryTypeDomain, normalized, true
}

func normalizeURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	parsed.Fragment = ""
	parsed.Host = strings.ToLower(parsed.Host)
	if parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.String()
}

func normalizeDomain(raw string) string {
	clean := strings.TrimSpace(strings.ToLower(raw))
	clean = strings.TrimPrefix(clean, ".")
	clean = cutAtDelims(clean, "/^\\")
	if clean == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(clean); err == nil {
		clean = host
	}
	return clean
}

func cutAtDelims(value string, delims string) string {
	for _, r := range delims {
		if idx := strings.IndexRune(value, r); idx >= 0 {
			return value[:idx]
		}
	}
	return value
}
