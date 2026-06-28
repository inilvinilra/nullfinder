package report

import (
	"sort"

	"nullfinder/internal/storage"
)

// CountItem stores a label and its occurrence count for summary views.
type CountItem struct {
	Label string
	Count int
}

// ReportSummary aggregates high-signal counts for executive dashboards and text reports.
type ReportSummary struct {
	TotalAssets        int
	UniqueIPs          int
	UniquePorts        int
	UniqueWebEndpoints int
	InterestingAssets  int
	UniqueTechnologies int
	UniqueServers      int
	UniqueTitles       int
	EvidenceScore      int
	TopTechnologies    []CountItem
	TopServers         []CountItem
	TopTitles          []CountItem
}

// BuildSummary computes a compact, comparable view of a scan result set.
func BuildSummary(assets []storage.AssetRecord) ReportSummary {
	summary := ReportSummary{TotalAssets: len(assets)}
	ipSet := make(map[string]struct{})
	portSet := make(map[int]struct{})
	webSet := make(map[string]struct{})
	techCounts := make(map[string]int)
	serverCounts := make(map[string]int)
	titleCounts := make(map[string]int)

	for _, a := range assets {
		if a.IsInteresting {
			summary.InterestingAssets++
		}
		for _, ip := range a.IPs {
			if ip == "" {
				continue
			}
			ipSet[ip] = struct{}{}
		}
		for _, port := range a.Ports {
			portSet[port] = struct{}{}
		}
		for _, scheme := range a.Schemes {
			if scheme == "" {
				continue
			}
			webSet[scheme] = struct{}{}
		}
		for _, tech := range a.Technologies {
			if tech == "" {
				continue
			}
			techCounts[tech]++
		}
		for _, server := range a.Servers {
			if server == "" {
				continue
			}
			serverCounts[server]++
		}
		for _, title := range a.Titles {
			if title == "" {
				continue
			}
			titleCounts[title]++
		}
	}

	summary.UniqueIPs = len(ipSet)
	summary.UniquePorts = len(portSet)
	summary.UniqueWebEndpoints = len(webSet)
	summary.UniqueTechnologies = len(techCounts)
	summary.UniqueServers = len(serverCounts)
	summary.UniqueTitles = len(titleCounts)

	summary.TopTechnologies = topCounts(techCounts, 5)
	summary.TopServers = topCounts(serverCounts, 5)
	summary.TopTitles = topCounts(titleCounts, 5)

	score := 10
	score += min(summary.TotalAssets*2, 20)
	score += min(summary.UniqueIPs*2, 20)
	score += min(summary.UniquePorts*2, 15)
	score += min(summary.UniqueWebEndpoints*3, 15)
	score += min(summary.UniqueTechnologies*2, 10)
	score += min(summary.InterestingAssets*5, 10)
	if score > 100 {
		score = 100
	}
	summary.EvidenceScore = score

	return summary
}

func topCounts(counts map[string]int, limit int) []CountItem {
	items := make([]CountItem, 0, len(counts))
	for label, count := range counts {
		items = append(items, CountItem{Label: label, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Label < items[j].Label
		}
		return items[i].Count > items[j].Count
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
