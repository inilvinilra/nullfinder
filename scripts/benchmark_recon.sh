#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <domain> [output-dir]" >&2
  exit 1
fi

DOMAIN="$1"
OUT_DIR="${2:-benchmark/${DOMAIN//./-}}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/bin/nullfinder"
PORTS="80,443,8080,8443"

mkdir -p "${OUT_DIR}"

run_with_timeout() {
  local seconds="$1"
  shift
  timeout --foreground --kill-after=5s --signal=INT "${seconds}" "$@"
}

run_tool() {
  local name="$1"
  local seconds="$2"
  shift 2
  echo "[*] ${name}"
  if ! run_with_timeout "${seconds}" "$@"; then
    echo "[warn] ${name} failed or timed out" >&2
  fi
}

have_tool() {
  command -v "$1" >/dev/null 2>&1
}

append_if_exists() {
  local file="$1"
  if [[ -f "${file}" ]]; then
    ENUM_FILES+=("${file}")
  fi
}

count_lines() {
  local file="$1"
  if [[ -f "${file}" ]]; then
    wc -l < "${file}" | tr -d ' '
  else
    echo "0"
  fi
}

count_nullfinder_domain_ports() {
  local json_file="$1"
  if [[ ! -f "${json_file}" ]]; then
    echo "0"
    return
  fi

  python - "${json_file}" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
print(len({(row.get("domain", ""), row.get("port", 0)) for row in data}))
PY
}

resolve_verified_output() {
  local input_file="$1"
  local output_file="$2"
  if [[ ! -f "${input_file}" ]]; then
    : > "${output_file}"
    return
  fi

  if have_tool dnsx; then
    dnsx -silent -l "${input_file}" -retry 2 -rl 20 -o "${output_file}" >/dev/null 2>&1 || : > "${output_file}"
  else
    sort -u "${input_file}" > "${output_file}"
  fi
}

resolve_ipv4_targets() {
  local input_file="$1"
  local output_file="$2"
  : > "${output_file}"

  while IFS= read -r host; do
    [[ -z "${host}" ]] && continue
    getent ahostsv4 "${host}" | awk '{print $1}' >> "${output_file}" || true
  done < "${input_file}"

  sort -u "${output_file}" -o "${output_file}"
}

summary_row() {
  printf "%-24s %8s\n" "$1" "$2" >> "${SUMMARY_FILE}"
}

echo "[*] Building NullFinder"
(
  cd "${ROOT_DIR}"
  go build -buildvcs=false -o "${BIN}" ./cmd/nullfinder
)

SUMMARY_FILE="${OUT_DIR}/summary.txt"
: > "${SUMMARY_FILE}"
printf "%-24s %8s\n" "Tool" "Count" >> "${SUMMARY_FILE}"
printf "%-24s %8s\n" "------------------------" "--------" >> "${SUMMARY_FILE}"

run_tool "NullFinder passive" 90 bash -lc "cd '${ROOT_DIR}' && '${BIN}' enum --domain '${DOMAIN}' --mode passive --threads 10 --rate-limit 10 --output '${OUT_DIR}/nullfinder-passive'"
run_tool "NullFinder hybrid" 90 bash -lc "cd '${ROOT_DIR}' && '${BIN}' enum --domain '${DOMAIN}' --mode hybrid --threads 10 --rate-limit 10 --output '${OUT_DIR}/nullfinder-hybrid'"

if have_tool subfinder; then
  run_tool "subfinder" 60 bash -lc "cd '${ROOT_DIR}' && subfinder -d '${DOMAIN}' -all -silent -o '${OUT_DIR}/subfinder.txt'"
fi

if have_tool assetfinder; then
  run_tool "assetfinder" 30 bash -lc "cd '${ROOT_DIR}' && assetfinder --subs-only '${DOMAIN}' > '${OUT_DIR}/assetfinder.txt'"
fi

if have_tool amass; then
  run_tool "amass passive" 120 bash -lc "cd '${ROOT_DIR}' && amass enum -passive -d '${DOMAIN}' -oA '${OUT_DIR}/amass' -nocolor"
fi

resolve_verified_output "${OUT_DIR}/subfinder.txt" "${OUT_DIR}/subfinder_verified.txt"
resolve_verified_output "${OUT_DIR}/assetfinder.txt" "${OUT_DIR}/assetfinder_verified.txt"
resolve_verified_output "${OUT_DIR}/amass.txt" "${OUT_DIR}/amass_verified.txt"

ENUM_FILES=()
while IFS= read -r file; do
  ENUM_FILES+=("${file}")
done < <(find "${OUT_DIR}" -name all_subdomains.txt -type f | sort)

append_if_exists "${OUT_DIR}/subfinder.txt"
append_if_exists "${OUT_DIR}/assetfinder.txt"
append_if_exists "${OUT_DIR}/amass.txt"

if [[ ${#ENUM_FILES[@]} -eq 0 ]]; then
  echo "[!] No enumeration outputs found" >&2
  exit 1
fi

UNION_FILE="${OUT_DIR}/union.txt"
sort -u "${ENUM_FILES[@]}" > "${UNION_FILE}"

if have_tool dnsx; then
  run_tool "dnsx resolve" 60 bash -lc "cd '${ROOT_DIR}' && dnsx -silent -l '${UNION_FILE}' -retry 2 -rl 20 -o '${OUT_DIR}/dnsx_hosts.txt'"
else
  cp "${UNION_FILE}" "${OUT_DIR}/dnsx_hosts.txt"
fi

resolve_ipv4_targets "${OUT_DIR}/dnsx_hosts.txt" "${OUT_DIR}/masscan_targets.txt"

run_tool "NullFinder HTTP" 120 bash -lc "cd '${ROOT_DIR}' && '${BIN}' --threads 10 --rate-limit 20 --output '${OUT_DIR}/nullfinder-http' http --input '${OUT_DIR}/dnsx_hosts.txt' --ports ${PORTS}"
run_tool "NullFinder ports" 90 bash -lc "cd '${ROOT_DIR}' && '${BIN}' --threads 10 --rate-limit 20 --output '${OUT_DIR}/nullfinder-ports' ports --input '${OUT_DIR}/dnsx_hosts.txt' --ports-list ${PORTS}"

if have_tool naabu; then
  run_tool "naabu" 90 bash -lc "cd '${ROOT_DIR}' && naabu -silent -list '${OUT_DIR}/dnsx_hosts.txt' -p ${PORTS} -rate 20 -o '${OUT_DIR}/naabu.txt'"
fi

if have_tool rustscan; then
  run_tool "rustscan" 90 bash -lc "cd '${ROOT_DIR}' && exec rustscan -a \$(tr '\n' ',' < '${OUT_DIR}/dnsx_hosts.txt' | sed 's/,\$//') --ulimit 256 --batch-size 10 --timeout 2000 --tries 1 --scan-order Serial -- -Pn -p ${PORTS} > '${OUT_DIR}/rustscan.txt'"
fi

if have_tool nmap; then
  run_tool "nmap" 120 bash -lc "cd '${ROOT_DIR}' && nmap -Pn -p ${PORTS} -iL '${OUT_DIR}/dnsx_hosts.txt' -oN '${OUT_DIR}/nmap.txt'"
fi

if have_tool masscan; then
  run_tool "masscan" 90 bash -lc "cd '${ROOT_DIR}' && if [[ -s '${OUT_DIR}/masscan_targets.txt' ]]; then masscan -p${PORTS} -iL '${OUT_DIR}/masscan_targets.txt' --rate 50 -oL '${OUT_DIR}/masscan.txt'; else exit 0; fi"
fi

summary_row "nullfinder-passive" "$(find "${OUT_DIR}/nullfinder-passive" -name all_subdomains.txt -type f -exec wc -l {} + 2>/dev/null | tail -n 1 | awk '{print $1+0}')"
summary_row "nf-passive-candidates" "$(find "${OUT_DIR}/nullfinder-passive" -name candidate_subdomains.txt -type f -exec wc -l {} + 2>/dev/null | tail -n 1 | awk '{print $1+0}')"
summary_row "nullfinder-hybrid" "$(find "${OUT_DIR}/nullfinder-hybrid" -name all_subdomains.txt -type f -exec wc -l {} + 2>/dev/null | tail -n 1 | awk '{print $1+0}')"
summary_row "nf-hybrid-candidates" "$(find "${OUT_DIR}/nullfinder-hybrid" -name candidate_subdomains.txt -type f -exec wc -l {} + 2>/dev/null | tail -n 1 | awk '{print $1+0}')"
summary_row "subfinder" "$(count_lines "${OUT_DIR}/subfinder.txt")"
summary_row "subfinder-verified" "$(count_lines "${OUT_DIR}/subfinder_verified.txt")"
summary_row "assetfinder" "$(count_lines "${OUT_DIR}/assetfinder.txt")"
summary_row "assetfinder-verified" "$(count_lines "${OUT_DIR}/assetfinder_verified.txt")"
summary_row "amass" "$(count_lines "${OUT_DIR}/amass.txt")"
summary_row "amass-verified" "$(count_lines "${OUT_DIR}/amass_verified.txt")"
summary_row "union" "$(count_lines "${UNION_FILE}")"
summary_row "dnsx-hosts" "$(count_lines "${OUT_DIR}/dnsx_hosts.txt")"
summary_row "masscan-targets" "$(count_lines "${OUT_DIR}/masscan_targets.txt")"
summary_row "nullfinder-http" "$(find "${OUT_DIR}/nullfinder-http" -name live_urls.txt -type f -exec wc -l {} + 2>/dev/null | tail -n 1 | awk '{print $1+0}')"
summary_row "nullfinder-ports" "$(find "${OUT_DIR}/nullfinder-ports" -name open_ports.txt -type f -exec wc -l {} + 2>/dev/null | tail -n 1 | awk '{print $1+0}')"
summary_row "nf-ports-domainport" "$(count_nullfinder_domain_ports "$(find "${OUT_DIR}/nullfinder-ports" -name portscan_results.json -type f | head -n 1)")"
summary_row "naabu" "$(count_lines "${OUT_DIR}/naabu.txt")"
summary_row "rustscan" "$(grep -c '^Open ' "${OUT_DIR}/rustscan.txt" 2>/dev/null || true)"
summary_row "nmap-open" "$(grep -c ' open ' "${OUT_DIR}/nmap.txt" 2>/dev/null || true)"
summary_row "masscan" "$(grep -c '^open' "${OUT_DIR}/masscan.txt" 2>/dev/null || true)"

echo
echo "[done] Benchmark outputs written to ${OUT_DIR}"
cat "${SUMMARY_FILE}"
