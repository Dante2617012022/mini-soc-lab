#!/usr/bin/env bash
set -Eeuo pipefail

PATH="${PATH}:/usr/sbin:/sbin"

usage() {
  cat <<'EOF'
Usage: bash scripts/endpoint/check-wazuh-agent-readiness.sh

Read-only readiness gate for SOC-ENDPOINT-01 before Wazuh Agent deployment.
It changes no system configuration and installs no packages.
EOF
}

if [[ $# -gt 0 ]]; then
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unexpected argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
fi

failures=0

pass() {
  printf 'PASS: %s\n' "$1"
}

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

info() {
  printf 'INFO: %s\n' "$1"
}

expected_hostname="SOC-ENDPOINT-01"

if [[ "$(hostname)" == "$expected_hostname" ]]; then
  pass "hostname is $expected_hostname"
else
  fail "hostname is $(hostname), expected $expected_hostname"
fi

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  info "operating system: ${PRETTY_NAME:-unknown}"
  if [[ "${ID:-}" == "debian" ]]; then
    pass "Debian OS family detected"
  else
    fail "expected Debian OS family, found ${ID:-unknown}"
  fi
else
  fail "/etc/os-release is not readable"
fi

info "architecture: $(uname -m)"
info "kernel: $(uname -r)"

for unit in ssh systemd-journald systemd-timesyncd; do
  if systemctl is-active --quiet "$unit"; then
    pass "$unit is active"
  else
    fail "$unit is not active"
  fi
done

if [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)" == "yes" ]]; then
  pass "system clock is synchronized"
else
  fail "system clock is not synchronized"
fi

if [[ -d /var/log/journal ]]; then
  pass "persistent journal directory exists"
else
  fail "persistent journal directory /var/log/journal is missing"
fi

if dpkg-query -W -f='${Status}' wazuh-agent 2>/dev/null | grep -Fxq 'install ok installed'; then
  fail "wazuh-agent is already installed; CHG-006 expects a pre-install state"
else
  pass "wazuh-agent is not installed"
fi

if grep -Rqs --include='*.list' --include='*.sources' 'packages\.wazuh\.com' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
  fail "a Wazuh APT repository is already configured"
else
  pass "no Wazuh APT repository is configured"
fi

if command -v apt-get >/dev/null 2>&1; then
  pass "apt-get is available for the later controlled deployment"
else
  fail "apt-get is not available"
fi

info "root filesystem free space: $(df -hP / | awk 'NR==2 {print $4}')"
info "no host configuration was changed"

if (( failures > 0 )); then
  printf '\nReadiness result: FAIL (%d condition(s))\n' "$failures" >&2
  exit 1
fi

printf '\nReadiness result: PASS\n'
