package analyzer

import (
	"regexp"
	"strings"
	"time"

	"github.com/likexian/whois"
	"github.com/likexian/whois-parser"
)

// GetDomainAgeDays retrieves the age of a domain in days using WHOIS data.
func GetDomainAgeDays(domain string) int {
	raw, err := whois.Whois(domain)
	if err != nil {
		return -1
	}
	result, err := whoisparser.Parse(raw)
	if err != nil {
		return -1
	}

	created := result.Domain.CreatedDate
	if created == "" {
		// fallback: try to find created date in raw WHOIS
		re := regexp.MustCompile(`(?i)created:\s*([0-9]{8})`)
		if match := re.FindStringSubmatch(raw); len(match) == 2 {
			// only first 8 digits, ignore suffix
			created = match[1][:4] + "-" + match[1][4:6] + "-" + match[1][6:8]
		}
	}
	if strings.Contains(created, "#") {
		// remove suffix like "#4444540"
		created = strings.TrimSpace(strings.Split(created, " ")[0])
	}
	if created == "" {
		return -1
	}

	// Convert raw YYYYMMDD to YYYY-MM-DD if needed
	if len(created) == 8 && strings.Count(created, "-") == 0 {
		created = created[:4] + "-" + created[4:6] + "-" + created[6:8]
	}

	t, err := time.Parse("2006-01-02", created)
	if err != nil {
		layouts := []string{
			"2006-01-02T15:04:05Z",
			"2006.01.02 15:04:05",
		}
		for _, layout := range layouts {
			t, err = time.Parse(layout, created)
			if err == nil {
				break
			}
		}
	}
	if t.IsZero() {
		return -1
	}
	return int(time.Since(t).Hours() / 24)
}
