package enum

import "time"

// AssetSource records where and when a subdomain was found.
type AssetSource struct {
	Provider string    `json:"provider"`
	Type     string    `json:"type"`
	SeenAt   time.Time `json:"seen_at"`
}

// Asset represents a unified, deduplicated subdomain candidate.
type Asset struct {
	Subdomain  string        `json:"subdomain"`
	Sources    []AssetSource `json:"sources"`
	Confidence int           `json:"confidence"`
}
