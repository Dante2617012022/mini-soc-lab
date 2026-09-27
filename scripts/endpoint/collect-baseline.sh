#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
PATH="${PATH}:/usr/sbin:/sbin"

usage() {
  cat <<'EOF'
Usage: bash scripts/endpoint/collect-baseline.sh [--output-dir PATH]

Collects a read-only baseline from a Debian endpoint.
Default output directory: ~/soc-evidence/baseline

The script does not change system configuration.
If a cached sudo credential is available, it also records privileged
listening-port and nftables information. It never prompts for sudo.
EOF
}

output_dir="${HOME}/soc-evidence/baseline"

while [[ $# -gt 0 ]]; do
  case "$1" in
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

mkdir -p "$output_dir"
timestamp="$(date -u +'%Y%m%dT%H%M%SZ')"
report="${output_dir}/baseline-${timestamp}.txt"
checksum="${report}.sha256"

section() {
  printf '\n===== %s =====\n' "$1"
}

run_optional() {
  local label="$1"
  shift
  section "$label"
  "$@" 2>&1 || true
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

{
  echo "MINI-SOC ENDPOINT BASELINE"
  echo "Collected UTC: $(date -u -Is)"
  echo "Purpose: read-only pre-change evidence"

  run_optional "IDENTITY" hostnamectl
  run_optional "OPERATING SYSTEM" cat /etc/os-release
  run_optional "KERNEL" uname -a

  if have_cmd lscpu; then
    section "CPU"
    lscpu | grep -E 'Architecture|CPU\(s\)|Model name' || true
  fi

  run_optional "MEMORY" free -h
  run_optional "ROOT FILESYSTEM" df -h /
  run_optional "NETWORK INTERFACES" ip -br address
  run_optional "ROUTING" ip route

  section "DNS"
  if [[ -r /etc/resolv.conf ]]; then
    cat /etc/resolv.conf
  else
    echo "UNAVAILABLE: /etc/resolv.conf is not readable"
  fi

  section "LISTENING PORTS"
  if have_cmd sudo && sudo -n true 2>/dev/null; then
    sudo -n ss -tulpn 2>&1 || true
  else
    ss -tuln 2>&1 || true
    echo "NOTE: privileged process details skipped; no cached passwordless sudo session."
  fi

  run_optional "ENABLED SERVICES" systemctl list-unit-files --state=enabled --no-pager
  run_optional "RUNNING SERVICES" systemctl --type=service --state=running --no-pager

  section "LOCAL INTERACTIVE USERS"
  awk -F: '$3 >= 1000 && $7 !~ /(nologin|false)$/ {print $1, $3, $6, $7}' /etc/passwd || true

  run_optional "CURRENT USER AND GROUPS" id
  run_optional "SUDO GROUP" getent group sudo
  run_optional "DOCKER GROUP" getent group docker

  section "FIREWALL RULESET"
  if have_cmd nft; then
    if have_cmd sudo && sudo -n true 2>/dev/null; then
      sudo -n nft list ruleset 2>&1 || true
    else
      nft list ruleset 2>&1 || true
      echo "NOTE: full nftables ruleset may require root privileges."
    fi
  else
    echo "nft command not available in PATH"
  fi

  section "SECURITY-RELEVANT PACKAGES"
  dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null |
    grep -E '^(openssh|auditd|nftables|suricata|yara|wazuh)' || true

  section "CONNECTIVITY"
  if have_cmd ping; then
    ping -c 3 -W 2 1.1.1.1 2>&1 || true
    echo
    ping -c 3 -W 2 deb.debian.org 2>&1 || true
  else
    echo "ping command not installed"
  fi
} | tee "$report"

sha256sum "$report" | tee "$checksum"

echo
echo "Baseline written to: $report"
echo "Checksum written to: $checksum"
echo "Do not commit raw baseline output to this public repository."
