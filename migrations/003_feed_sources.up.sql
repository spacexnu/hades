-- Feed sources and entries for open blocklists

CREATE TABLE IF NOT EXISTS feed_sources (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL,
    category VARCHAR(32) NOT NULL DEFAULT 'phishing',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS feed_entries (
    id BIGSERIAL PRIMARY KEY,
    source_id INT NOT NULL REFERENCES feed_sources(id) ON DELETE CASCADE,
    entry_type VARCHAR(16) NOT NULL,
    value TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS feed_entries_source_unique
    ON feed_entries (source_id, entry_type, value);

CREATE INDEX IF NOT EXISTS feed_entries_lookup_idx
    ON feed_entries (entry_type, value);

INSERT INTO feed_sources (name, url, category, enabled) VALUES
    ('phishing_database_links', 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt', 'phishing', TRUE),
    ('phishing_database_domains', 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt', 'phishing', TRUE),
    ('openphish_links', 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt', 'phishing', TRUE),
    ('phishing_database_links_new', 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-NEW-today.txt', 'phishing', TRUE),
    ('phishing_database_domains_new', 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-NEW-today.txt', 'phishing', TRUE),
    ('spam404_domains', 'https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt', 'phishing', TRUE),
    ('kad_hosts', 'https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt', 'phishing', TRUE)
ON CONFLICT DO NOTHING;
