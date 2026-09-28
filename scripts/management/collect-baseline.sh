#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
PATH="${PATH}:/usr/sbin:/sbin"

usage() {
  cat <<'EOF'
Usage: bash scripts/management/collect-baseline.sh [--output-dir PATH]

Collects a read-only baseline from SOC-MGMT-01 before Wazuh installation.
Default output directory: ~/soc-evidence/baseline

The script does not change system configuration.
Run with sudo/root if privileged listener and firewall details are required.
Raw output is private evidence and must not be committed.
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
report="${output_dir}/soc-mgmt-01-baseline-${timestamp}.txt"
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

is_root() {
  [[ "${EUID}" -eq 0 ]]
}

{
  echo "MINI-SOC MANAGEMENT BASELINE"
  echo "Collected UTC: $(date -u -Is)"
  echo "Classification: PRIVATE RAW EVIDENCE — DO NOT COMMIT"
  echo "Purpose: pre-Wazuh SOC-MGMT-01 baseline"

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

  run_optional "TIME" timedatectl

  section "LISTENING PORTS"
  if is_root; then
    ss -tulpn 2>&1 || true
  else
    ss -tuln 2>&1 || true
    echo "NOTE: process details omitted because the collector is not running as root."
  fi

  run_optional "ENABLED SERVICES" systemctl list-unit-files --state=enabled --no-pager
  run_optional "RUNNING SERVICES" systemctl --type=service --state=running --no-pager

  section "LOCAL INTERACTIVE USERS"
  awk -F: '$3 >= 1000 && $7 !~ /(nologin|false)$/ {print $1, $3, $6, $7}' /etc/passwd || true

  run_optional "CURRENT USER AND GROUPS" id
  run_optional "SUDO GROUP" getent group sudo
  run_optional "DOCKER GROUP" getent group docker

  section "FIREWALL"
  if have_cmd ufw; then
    if is_root; then
      ufw status verbose 2>&1 || true
    else
      ufw status 2>&1 || true
      echo "NOTE: detailed UFW status may require root privileges."
    fi
  else
    echo "ufw command not available"
  fi

  if have_cmd nft; then
    echo
    echo "--- nftables ruleset ---"
    if is_root; then
      nft list ruleset 2>&1 || true
    else
      nft list ruleset 2>&1 || true
      echo "NOTE: full nftables ruleset may require root privileges."
    fi
  else
    echo "nft command not available"
  fi

  section "SECURITY-RELEVANT PACKAGES"
  dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null |
    grep -E '^(openssh|auditd|ufw|nftables|docker|wazuh)' || true

  section "WAZUH PRE-INSTALL STATE"
  if dpkg-query -W -f='${Status}' wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null |
      grep -Fq 'install ok installed'; then
    echo "WARNING: one or more Wazuh central packages appear installed."
  else
    echo "No Wazuh central package detected."
  fi

  section "APT SOURCES CONTAINING WAZUH"
  grep -R -n --include='*.list' --include='*.sources' 'packages\.wazuh\.com'     /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null || true
} | tee "$report"

sha256sum "$report" | tee "$checksum"

echo
echo "Baseline written to: $report"
echo "Checksum written to: $checksum"
echo "Do not commit raw baseline output to this public repository."
