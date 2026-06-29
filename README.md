# NullFinder

NullFinder is a native Go reconnaissance platform for authorized security testing, asset inventory, and bug bounty workflows.

It performs subdomain discovery, DNS resolution, HTTP probing, conservative TCP connect scanning, fingerprinting, and report generation in a single pipeline.

## Core Capabilities

- Passive OSINT aggregation
- Local wordlist and permutation-based discovery
- DNS resolution with wildcard filtering
- HTTP/HTTPS probing with redirects, TLS metadata, titles, headers, and technology hints
- Safe TCP connect port scanning with banner fingerprinting
- Honeypot detection based on service banners, headers, and protocol anomalies
- HTML, JSON, CSV, and TXT reporting

## Requirements

- Go 1.26 or newer
- Optional external tools for comparison and benchmarking:
  `dnsx`, `subfinder`, `assetfinder`, `amass`, `naabu`, `rustscan`, `nmap`, `masscan`

## Build

```bash
git clone <repo-url>
cd nullfinder
make build
```

Binary output:

- `./bin/nullfinder`

## Install

```bash
make release
```

Cross-platform artifacts are written to `./dist/`.

## Docker

```bash
docker build -t nullfinder .
```

## Configuration

Copy the example configuration and adjust values for your environment:

```bash
cp configs/config.example.yaml config.yaml
```

Environment variables for optional premium passive sources:

```bash
export SECURITYTRAILS_API_KEY="..."
export SHODAN_API_KEY="..."
export CENSYS_API_ID="..."
export CENSYS_API_SECRET="..."
```

## Usage

```bash
nullfinder scan --domain example.com --mode hybrid
nullfinder batch --domains-file targets/domains.txt --ips-file targets/ips.txt
nullfinder batch --domains-file targets/domains.txt --ips-file targets/ips.txt --mode full --ports 80,443,8080,8443 --max-port-targets 1000
nullfinder compare --domains-file targets/domains.txt --ips-file targets/ips.txt
nullfinder enum --domain example.com --mode passive
nullfinder dns --input subdomains.txt
nullfinder http --input resolved_subdomains.txt
nullfinder ports --input resolved_subdomains.txt --profile web
nullfinder report --scan-id example-com-2026-06-23-120000
```

Target list templates:

- [targets/domains.txt](/home/null/Desktop/NıulFinder/scoperecon/targets/domains.txt)
- [targets/ips.txt](/home/null/Desktop/NıulFinder/scoperecon/targets/ips.txt)

The `batch` command discovers assets from domains, forwards resolved IPs into HTTP and port analysis, merges direct IP targets, and writes a single combined report.

For large target sets, prefer a narrow first pass with `--ports` or `--max-port-targets`. Full `common` port analysis over thousands of resolved IPs can take a long time because every target/port pair is tested with a safe TCP connect timeout.

The `compare` command runs that same base pipeline first, then executes external tools in sequence. Subdomain tooling (`subfinder`, `assetfinder`, `amass`) is consolidated and verified before host-level comparison continues with `naabu`, `nmap`, `rustscan`, and optionally `masscan`.

## Output Layout

Primary scan output is written to `results/{scan-id}/`:

- `report.html`
- `report.json`
- `report.csv`
- `report.txt`
- `all_subdomains.txt`
- `resolved_subdomains.txt`
- `resolved_ips.txt`
- `domain_ip_map.txt`
- `candidate_subdomains.txt`
- `live_urls.txt`
- `open_ports.txt`
- `comparison/`

When `compare` is used, the `comparison/` folder contains per-tool outputs plus `comparison_summary.json` and `comparison_summary.txt`. `masscan` requires elevated privileges or Linux capabilities such as `cap_net_raw`; otherwise its failure is recorded in the comparison summary without stopping the rest of the workflow.

## Safety Model

NullFinder is designed for authorized, non-intrusive recon only:

- No raw SYN scanning
- No exploit payloads
- No credential brute forcing
- Scope validation before active stages
- Rate limiting and timeouts on network operations

## Included Components

- Passive provider aggregation
- DNS resolution and wildcard detection
- HTTP probing with enrichment
- TCP connect scanning and service fingerprinting
- Structured reporting and a local REST dashboard
