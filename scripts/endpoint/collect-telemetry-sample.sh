#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
PATH="${PATH}:/usr/sbin:/sbin"

usage() {
  cat <<'EOF'
Usage: bash scripts/endpoint/collect-telemetry-sample.sh [--since DURATION] [--output-dir PATH]

Collects read-only SOC-ENDPOINT-01 telemetry evidence from journald.
Defaults:
  --since "30 minutes ago"
  --output-dir ~/soc-evidence/telemetry

Run as root so the report can include the complete system journal.
The script changes no system configuration. It writes only the local evidence
report and its SHA-256 checksum.
EOF
}

since="30 minutes ago"
output_dir="${HOME}/soc-evidence/telemetry"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --since)
      [[ $# -ge 2 ]] || { echo "ERROR: --since requires a value" >&2; exit 2; }
      since="$2"
      shift 2
      ;;
    --output-dir)
      [[ $# -ge 2 ]] || { echo "ERROR: --output-dir requires a path" >&2; exit 2; }
      output_dir="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: run as root to access complete system journal evidence." >&2
  exit 1
fi

mkdir -p "$output_dir"
timestamp="$(date -u +'%Y%m%dT%H%M%SZ')"
report="${output_dir}/telemetry-${timestamp}.txt"
checksum="${report}.sha256"

section() {
  printf '\n===== %s =====\n' "$1"
}

{
  echo "MINI-SOC ENDPOINT TELEMETRY SAMPLE"
  echo "Collected UTC: $(date -u -Is)"
  echo "Window: $since"
  echo "Classification: PRIVATE RAW EVIDENCE — DO NOT COMMIT"

  section "CLOCK"
  timedatectl

  section "PERSISTENT JOURNAL BOOTS"
  journalctl --list-boots --no-pager

  section "SSH SERVICE EVENTS"
  journalctl --since "$since" -u ssh.service --no-pager -o short-iso || true

  section "SU PRIVILEGE EVENTS"
  journalctl --since "$since" _COMM=su --no-pager -o short-iso || true

  section "SSH SERVICE STATE"
  systemctl is-active ssh || true

  section "JOURNAL SERVICE STATE"
  systemctl is-active systemd-journald || true

  section "TIME SYNC SERVICE STATE"
  systemctl is-active systemd-timesyncd || true
} | tee "$report"

sha256sum "$report" | tee "$checksum"

echo
echo "Telemetry evidence written to: $report"
echo "Checksum written to: $checksum"
echo "Do not commit the raw report to the public repository."
