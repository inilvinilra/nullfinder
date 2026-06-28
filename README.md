# NullFinder

NullFinder is a native Go reconnaissance platform for authorized security testing, asset inventory, and bug bounty workflows.

It performs subdomain discovery, DNS resolution, HTTP probing, conservative TCP connect scanning, fingerprinting, and report generation in a single pipeline.

## Core Capabilities

- Passive OSINT aggregation
- Local wordlist and permutation-based discovery
- DNS resolution with wildcard filtering
- HTTP/HTTPS probing with redirects, TLS metadata, titles, headers, and technology hints
- Safe TCP connect port scanning with banner fingerprinting
- HTML, JSON, CSV, and TXT reporting
- Local benchmark matrix against `subfinder`, `assetfinder`, `amass`, `dnsx`, `naabu`, `rustscan`, `nmap`, and `masscan`

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
nullfinder enum --domain example.com --mode passive
nullfinder dns --input subdomains.txt
nullfinder http --input resolved_subdomains.txt
nullfinder ports --input resolved_subdomains.txt --profile web
nullfinder report --scan-id example-com-2026-06-23-120000
```

## Benchmarking

```bash
bash scripts/benchmark_recon.sh example.com
```

This runs NullFinder alongside the local comparison set and writes all benchmark outputs under `benchmark/`.

## Output Layout

Primary scan output is written to `results/{scan-id}/`:

- `report.html`
- `report.json`
- `report.csv`
- `report.txt`
- `all_subdomains.txt`
- `resolved_subdomains.txt`
- `candidate_subdomains.txt`
- `live_urls.txt`
- `open_ports.txt`

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
