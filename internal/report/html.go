package report

import (
	"html/template"
	"nullfinder/internal/storage"
	"os"
	"time"
)

// HTMLReportData aggregates properties for HTML template binding.
type HTMLReportData struct {
	TargetDomain       string
	ScanID             string
	Timestamp          string
	TotalSubdomains    int
	ActiveWebServices  int
	FlaggedAssets      int
	PotentialHoneypots int
	OpenPortsCount     int
	Summary            ReportSummary
	Assets             []storage.AssetRecord
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NullFinder Dashboard - {{.TargetDomain}}</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-main: #0b0f19;
            --bg-panel: #111827;
            --bg-subpanel: #1f2937;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --primary: #3b82f6;
            --accent: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --border: #374151;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-main);
            color: var(--text-main);
            font-family: 'Outfit', sans-serif;
            padding: 2rem;
            line-height: 1.5;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }

        .title-group h1 {
            font-size: 2.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, var(--primary), #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .title-group p {
            color: var(--text-muted);
            margin-top: 0.25rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
        }

        .meta-group {
            text-align: right;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            color: var(--text-muted);
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }

        .stat-card {
            background-color: var(--bg-panel);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            position: relative;
            overflow: hidden;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.4);
            border-color: var(--primary);
        }

        .stat-card h3 {
            font-size: 0.9rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }

        .stat-card .value {
            font-size: 2.25rem;
            font-weight: 800;
        }

        .stat-card.interesting .value {
            color: var(--warning);
        }

        .stat-card.honeypot .value {
            color: #f97316;
        }

        .stat-card.score .value {
            color: var(--accent);
        }

        .summary-panel {
            background: linear-gradient(180deg, rgba(17, 24, 39, 0.95), rgba(15, 23, 42, 0.98));
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }

        .summary-panel h2 {
            font-size: 1.1rem;
            margin-bottom: 1rem;
            color: var(--text-main);
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
        }

        .summary-block {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 12px;
            padding: 1rem;
        }

        .summary-block h3 {
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.06em;
            margin-bottom: 0.5rem;
        }

        .chip-list {
            display: flex;
            flex-wrap: wrap;
            gap: 0.4rem;
        }

        .chip {
            background: rgba(59, 130, 246, 0.12);
            border: 1px solid rgba(59, 130, 246, 0.25);
            color: #bfdbfe;
            border-radius: 999px;
            padding: 0.25rem 0.6rem;
            font-size: 0.8rem;
        }

        .search-container {
            margin-bottom: 1.5rem;
            display: flex;
            gap: 1rem;
        }

        .search-input {
            flex-grow: 1;
            background-color: var(--bg-panel);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 0.75rem 1rem;
            color: var(--text-main);
            font-family: inherit;
            font-size: 1rem;
            outline: none;
            transition: border-color 0.2s;
        }

        .search-input:focus {
            border-color: var(--primary);
        }

        .table-container {
            background-color: var(--bg-panel);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }

        th {
            background-color: var(--bg-subpanel);
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 0.05em;
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border);
        }

        td {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border);
            font-size: 0.95rem;
            vertical-align: middle;
        }

        tr:last-child td {
            border-bottom: none;
        }

        tr:hover td {
            background-color: rgba(255, 255, 255, 0.02);
        }

        .domain-cell {
            font-weight: 600;
            color: var(--text-main);
        }

        .ip-badge {
            font-family: 'JetBrains Mono', monospace;
            background-color: var(--bg-subpanel);
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            margin-right: 0.25rem;
            display: inline-block;
        }

        .port-badge {
            font-family: 'JetBrains Mono', monospace;
            background-color: rgba(59, 130, 246, 0.1);
            color: #60a5fa;
            border: 1px solid rgba(59, 130, 246, 0.3);
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            font-size: 0.8rem;
            margin-right: 0.25rem;
            display: inline-block;
        }

        .interesting-badge {
            background-color: rgba(245, 158, 11, 0.1);
            color: #fbbf24;
            border: 1px solid rgba(245, 158, 11, 0.3);
            padding: 0.2rem 0.5rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            display: inline-block;
        }

        .title-text {
            max-width: 250px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            display: inline-block;
            font-size: 0.85rem;
            color: var(--text-muted);
        }

        .live-link {
            color: var(--primary);
            text-decoration: none;
            transition: color 0.2s;
        }

        .live-link:hover {
            color: #60a5fa;
            text-decoration: underline;
        }
    </style>
</head>
<body>

    <header>
        <div class="title-group">
            <h1>NullFinder Dashboard</h1>
            <p>Scan Session ID: {{.ScanID}}</p>
        </div>
        <div class="meta-group">
            <div>Target Domain: <strong>{{.TargetDomain}}</strong></div>
            <div style="margin-top: 0.25rem;">Timestamp: {{.Timestamp}}</div>
        </div>
    </header>

    <div class="stats-grid">
        <div class="stat-card">
            <h3>Total Subdomains</h3>
            <div class="value">{{.TotalSubdomains}}</div>
        </div>
        <div class="stat-card">
            <h3>Active HTTP Services</h3>
            <div class="value">{{.ActiveWebServices}}</div>
        </div>
        <div class="stat-card interesting">
            <h3>Interesting Interfaces</h3>
            <div class="value">{{.FlaggedAssets}}</div>
        </div>
        <div class="stat-card honeypot">
            <h3>Potential Honeypots</h3>
            <div class="value">{{.PotentialHoneypots}}</div>
        </div>
        <div class="stat-card">
            <h3>Open TCP Ports</h3>
            <div class="value">{{.OpenPortsCount}}</div>
        </div>
        <div class="stat-card score">
            <h3>Evidence Score</h3>
            <div class="value">{{.Summary.EvidenceScore}}</div>
        </div>
    </div>

    <div class="summary-panel">
        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-block">
                <h3>Coverage</h3>
                <div class="chip-list">
                    <span class="chip">{{.Summary.UniqueIPs}} unique IPs</span>
                    <span class="chip">{{.Summary.UniquePorts}} unique ports</span>
                    <span class="chip">{{.Summary.UniqueWebEndpoints}} web endpoints</span>
                </div>
            </div>
            <div class="summary-block">
                <h3>Signal Depth</h3>
                <div class="chip-list">
                    <span class="chip">{{.Summary.UniqueTechnologies}} technologies</span>
                    <span class="chip">{{.Summary.UniqueServers}} servers</span>
                    <span class="chip">{{.Summary.UniqueTitles}} titles</span>
                    <span class="chip">{{.Summary.InterestingAssets}} flagged assets</span>
                    <span class="chip">{{.Summary.PotentialHoneypots}} honeypots</span>
                </div>
            </div>
            <div class="summary-block">
                <h3>Top Technologies</h3>
                <div class="chip-list">
                    {{range .Summary.TopTechnologies}}
                    <span class="chip">{{.Label}} ({{.Count}})</span>
                    {{else}}
                    <span class="chip">-</span>
                    {{end}}
                </div>
            </div>
        </div>
    </div>

    <div class="search-container">
        <input type="text" id="searchInput" class="search-input" placeholder="Search by subdomain, IP, port, title, or service...">
    </div>

    <div class="table-container">
        <table id="assetTable">
            <thead>
                <tr>
                    <th>Subdomain / Target</th>
                    <th>Resolved IPs</th>
                    <th>CNAME Info</th>
                    <th>Open Ports</th>
                    <th>Titles / Headers</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {{range .Assets}}
                <tr>
                    <td>
                        <span class="domain-cell">{{.Domain}}</span>
                        {{if .IsInteresting}}
                        <div style="margin-top: 0.25rem;">
                            <span class="interesting-badge" title="{{.InterestingReason}}">Interesting</span>
                        </div>
                        {{end}}
                        {{if .PotentialHoneypot}}
                        <div style="margin-top: 0.25rem;">
                            <span class="interesting-badge" style="background: rgba(249, 115, 22, 0.18); color: #fb923c; border-color: rgba(249, 115, 22, 0.35);" title="{{.HoneypotReason}}">Potential Honeypot</span>
                        </div>
                        {{end}}
                    </td>
                    <td>
                        {{range .IPs}}
                        <span class="ip-badge">{{.}}</span>
                        {{else}}
                        <span style="color: var(--text-muted); font-size: 0.85rem;">-</span>
                        {{end}}
                    </td>
                    <td>
                        {{range .CNAMEs}}
                        <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--text-muted);">{{.}}</span>
                        {{else}}
                        <span style="color: var(--text-muted); font-size: 0.85rem;">-</span>
                        {{end}}
                    </td>
                    <td>
                        {{range .Ports}}
                        <span class="port-badge">{{.}}</span>
                        {{else}}
                        <span style="color: var(--text-muted); font-size: 0.85rem;">-</span>
                        {{end}}
                    </td>
                    <td>
                        {{range .Titles}}
                        <span class="title-text" title="{{.}}">{{.}}</span>
                        {{else}}
                        <span style="color: var(--text-muted); font-size: 0.85rem;">-</span>
                        {{end}}
                    </td>
                    <td>
                        {{range .Schemes}}
                        <div style="font-size: 0.85rem;">
                            <a href="{{.}}" class="live-link" target="_blank">{{.}}</a>
                        </div>
                        {{else}}
                        <span style="color: var(--text-muted); font-size: 0.85rem;">No web interface</span>
                        {{end}}
                    </td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>

    <script>
        const searchInput = document.getElementById('searchInput');
        const assetTable = document.getElementById('assetTable');
        const rows = assetTable.getElementsByTagName('tbody')[0].getElementsByTagName('tr');

        searchInput.addEventListener('input', function() {
            const query = searchInput.value.toLowerCase();
            
            for (let i = 0; i < rows.length; i++) {
                const cells = rows[i].getElementsByTagName('td');
                let found = false;
                
                for (let j = 0; j < cells.length; j++) {
                    if (cells[j].textContent.toLowerCase().includes(query)) {
                        found = true;
                        break;
                    }
                }
                
                if (found) {
                    rows[i].style.display = '';
                } else {
                    rows[i].style.display = 'none';
                }
            }
        });
    </script>
</body>
</html>`

// ExportHTML compiles asset data into a stunning premium responsive single-page dashboard.
func ExportHTML(filePath string, targetDomain string, scanID string, assets []storage.AssetRecord) error {
	totalSubs := len(assets)
	activeWeb := 0
	flagged := 0
	honeypots := 0
	openPorts := 0

	for _, a := range assets {
		if len(a.Schemes) > 0 {
			activeWeb++
		}
		if a.IsInteresting {
			flagged++
		}
		if a.PotentialHoneypot {
			honeypots++
		}
		openPorts += len(a.Ports)
	}

	data := HTMLReportData{
		TargetDomain:       targetDomain,
		ScanID:             scanID,
		Timestamp:          time.Now().Format("2006-01-02 15:04:05 MST"),
		TotalSubdomains:    totalSubs,
		ActiveWebServices:  activeWeb,
		FlaggedAssets:      flagged,
		PotentialHoneypots: honeypots,
		OpenPortsCount:     openPorts,
		Summary:            BuildSummary(assets),
		Assets:             assets,
	}

	tmpl, err := template.New("dashboard").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	return tmpl.Execute(file, data)
}
