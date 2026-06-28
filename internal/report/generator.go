package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"nullfinder/internal/storage"
)

// ExportJSON writes a list of assets as structured JSON.
func ExportJSON(filePath string, assets []storage.AssetRecord) error {
	data, err := json.MarshalIndent(assets, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0644)
}

// ExportYAML writes a list of assets as YAML.
func ExportYAML(filePath string, assets []storage.AssetRecord) error {
	data, err := yaml.Marshal(assets)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0644)
}

// ExportCSV writes a spreadsheet-formatted CSV table.
func ExportCSV(filePath string, assets []storage.AssetRecord) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	err = writer.Write([]string{
		"Domain",
		"IPs",
		"CNAMEs",
		"Ports",
		"Schemes",
		"FinalURLs",
		"StatusCodes",
		"Titles",
		"Servers",
		"PoweredBy",
		"Technologies",
		"FaviconHashes",
		"ContentSecurityPolicies",
		"HasLoginForm",
		"TLSIssuers",
		"TLSExpiries",
		"IsInteresting",
		"InterestingReason",
		"PotentialHoneypot",
		"HoneypotReason",
	})
	if err != nil {
		return err
	}

	for _, a := range assets {
		ips := strings.Join(a.IPs, ";")
		cnames := strings.Join(a.CNAMEs, ";")

		var portsStrs []string
		for _, p := range a.Ports {
			portsStrs = append(portsStrs, strconv.Itoa(p))
		}
		ports := strings.Join(portsStrs, ";")

		schemes := strings.Join(a.Schemes, ";")
		finalURLs := strings.Join(a.FinalURLs, ";")

		var statusStrs []string
		for _, s := range a.StatusCodes {
			statusStrs = append(statusStrs, strconv.Itoa(s))
		}
		statusCodes := strings.Join(statusStrs, ";")

		titles := strings.Join(a.Titles, ";")
		servers := strings.Join(a.Servers, ";")
		poweredBy := strings.Join(a.PoweredBy, ";")
		technologies := strings.Join(a.Technologies, ";")
		faviconHashes := strings.Join(a.FaviconHashes, ";")
		csps := strings.Join(a.CSPs, ";")
		tlsIssuers := strings.Join(a.TLSIssuers, ";")
		tlsExpiries := strings.Join(a.TLSExpiries, ";")

		err = writer.Write([]string{
			a.Domain,
			ips,
			cnames,
			ports,
			schemes,
			finalURLs,
			statusCodes,
			titles,
			servers,
			poweredBy,
			technologies,
			faviconHashes,
			csps,
			strconv.FormatBool(a.HasLoginForm),
			tlsIssuers,
			tlsExpiries,
			strconv.FormatBool(a.IsInteresting),
			a.InterestingReason,
			strconv.FormatBool(a.PotentialHoneypot),
			a.HoneypotReason,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

// ExportTXT writes a human-readable text report.
func ExportTXT(filePath string, targetDomain string, scanID string, assets []storage.AssetRecord) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	summary := BuildSummary(assets)

	fmt.Fprintf(file, "NullFinder Scan Summary Report\n")
	fmt.Fprintf(file, "========================================\n")
	fmt.Fprintf(file, "Target Domain: %s\n", targetDomain)
	fmt.Fprintf(file, "Scan ID:       %s\n", scanID)
	fmt.Fprintf(file, "Total Assets:  %d\n\n", len(assets))
	fmt.Fprintf(file, "Evidence Score: %d/100\n", summary.EvidenceScore)
	fmt.Fprintf(file, "Unique IPs:    %d\n", summary.UniqueIPs)
	fmt.Fprintf(file, "Unique Ports:  %d\n", summary.UniquePorts)
	fmt.Fprintf(file, "Web Endpoints: %d\n", summary.UniqueWebEndpoints)
	fmt.Fprintf(file, "Technologies:  %d\n", summary.UniqueTechnologies)
	fmt.Fprintf(file, "Interesting:   %d\n\n", summary.InterestingAssets)
	fmt.Fprintf(file, "Honeypots:     %d\n\n", summary.PotentialHoneypots)

	if len(summary.TopTechnologies) > 0 {
		fmt.Fprintln(file, "Top Technologies:")
		for _, item := range summary.TopTechnologies {
			fmt.Fprintf(file, "- %s (%d)\n", item.Label, item.Count)
		}
		fmt.Fprintln(file)
	}

	var interesting []storage.AssetRecord
	for _, a := range assets {
		if a.IsInteresting {
			interesting = append(interesting, a)
		}
	}

	fmt.Fprintf(file, "=== Flagged Interesting Assets (%d) ===\n", len(interesting))
	for _, a := range interesting {
		fmt.Fprintf(file, "- Domain: %s\n", a.Domain)
		if len(a.IPs) > 0 {
			fmt.Fprintf(file, "  IPs:    %s\n", strings.Join(a.IPs, ", "))
		}
		if len(a.Ports) > 0 {
			var ports []string
			for _, p := range a.Ports {
				ports = append(ports, strconv.Itoa(p))
			}
			fmt.Fprintf(file, "  Ports:  %s\n", strings.Join(ports, ", "))
		}
		fmt.Fprintf(file, "  Reason: %s\n", a.InterestingReason)
		fmt.Fprintln(file)
	}

	var honeypots []storage.AssetRecord
	for _, a := range assets {
		if a.PotentialHoneypot {
			honeypots = append(honeypots, a)
		}
	}

	fmt.Fprintf(file, "=== Potential Honeypots (%d) ===\n", len(honeypots))
	for _, a := range honeypots {
		fmt.Fprintf(file, "- Domain: %s\n", a.Domain)
		if len(a.IPs) > 0 {
			fmt.Fprintf(file, "  IPs:    %s\n", strings.Join(a.IPs, ", "))
		}
		if len(a.Ports) > 0 {
			var ports []string
			for _, p := range a.Ports {
				ports = append(ports, strconv.Itoa(p))
			}
			fmt.Fprintf(file, "  Ports:  %s\n", strings.Join(ports, ", "))
		}
		fmt.Fprintf(file, "  Reason: %s\n", a.HoneypotReason)
		fmt.Fprintln(file)
	}

	fmt.Fprintf(file, "=== All Discovered Subdomains (%d) ===\n", len(assets))
	for _, a := range assets {
		cnameInfo := ""
		if len(a.CNAMEs) > 0 {
			cnameInfo = fmt.Sprintf(" (CNAME: %s)", strings.Join(a.CNAMEs, ", "))
		}
		fmt.Fprintf(file, "- %s%s\n", a.Domain, cnameInfo)
		if len(a.IPs) > 0 {
			fmt.Fprintf(file, "  IPs:    %s\n", strings.Join(a.IPs, ", "))
		}
		if len(a.Ports) > 0 {
			var pStr []string
			for _, p := range a.Ports {
				pStr = append(pStr, strconv.Itoa(p))
			}
			fmt.Fprintf(file, "  Ports:  %s\n", strings.Join(pStr, ", "))
		}
		if a.PotentialHoneypot {
			fmt.Fprintf(file, "  Honeypot: %s\n", a.HoneypotReason)
		}
	}

	return nil
}
