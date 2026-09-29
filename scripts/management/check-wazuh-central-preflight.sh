#!/usr/bin/env bash
set -Eeuo pipefail

PATH="${PATH}:/usr/sbin:/sbin"

usage() {
  cat <<'EOF'
Usage: bash scripts/management/check-wazuh-central-preflight.sh

Read-only preflight for installing the Wazuh all-in-one central stack on SOC-MGMT-01.
The script does not install packages or change system configuration.
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -ne 0 ]]; then
  echo "ERROR: unexpected argument: $1" >&2
  usage >&2
  exit 2
fi

failures=0

pass() {
  printf 'PASS: %s\n' "$1"
}

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

echo "MINI-SOC WAZUH CENTRAL PREFLIGHT"
echo "Mode: read-only"

expected_hostname="soc-mgmt-01"
actual_hostname="$(hostname)"
if [[ "$actual_hostname" == "$expected_hostname" ]]; then
  pass "hostname is $expected_hostname"
else
  fail "hostname is $actual_hostname; expected $expected_hostname"
fi

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
  if [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]]; then
    pass "operating system is Ubuntu 24.04 LTS family"
  else
    fail "expected Ubuntu 24.04; detected ID=${ID:-unknown} VERSION_ID=${VERSION_ID:-unknown}"
  fi
else
  fail "/etc/os-release is not readable"
fi

arch="$(uname -m)"
if [[ "$arch" == "x86_64" ]]; then
  pass "architecture is x86_64"
else
  fail "architecture is $arch; expected x86_64"
fi

cpu_count="$(nproc)"
if (( cpu_count >= 4 )); then
  pass "CPU allocation is $cpu_count vCPU"
else
  fail "CPU allocation is $cpu_count vCPU; expected at least 4"
fi

mem_kib="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
min_mem_kib=$((7 * 1024 * 1024))
if (( mem_kib >= min_mem_kib )); then
  pass "memory allocation is at least 7 GiB usable"
else
  fail "memory allocation is below the expected 8 GiB VM profile"
fi

free_kib="$(df -Pk / | awk 'NR==2 {print $4}')"
min_free_kib=$((30 * 1024 * 1024))
if (( free_kib >= min_free_kib )); then
  pass "root filesystem has at least 30 GiB free"
else
  fail "root filesystem has less than 30 GiB free"
fi

system_state="$(systemctl is-system-running 2>/dev/null || true)"
if [[ "$system_state" == "running" ]]; then
  pass "systemd reports running"
else
  fail "systemd state is $system_state"
fi

failed_units="$(systemctl --failed --no-legend --plain 2>/dev/null | sed '/^[[:space:]]*$/d' | wc -l)"
if [[ "$failed_units" -eq 0 ]]; then
  pass "no failed systemd units"
else
  fail "$failed_units failed systemd unit(s) detected"
fi

ntp_sync="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
if [[ "$ntp_sync" == "yes" ]]; then
  pass "system clock is synchronized"
else
  fail "system clock is not synchronized"
fi

for pkg in wazuh-manager wazuh-indexer wazuh-dashboard filebeat; do
  if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -Fq 'install ok installed'; then
    fail "$pkg is already installed"
  else
    pass "$pkg is not installed"
  fi
done

if grep -R -q --include='*.list' --include='*.sources' 'packages\.wazuh\.com' \
    /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
  fail "Wazuh APT repository is already configured"
else
  pass "Wazuh APT repository is not configured"
fi

listeners="$(ss -H -ltn 2>/dev/null | awk '{print $4}')"
for port in 443 1514 1515 55000 9200; do
  if grep -Eq ":${port}$" <<<"$listeners"; then
    fail "TCP/$port is already listening before Wazuh installation"
  else
    pass "TCP/$port is free"
  fi
done

if command -v curl >/dev/null 2>&1; then
  pass "curl is available"
else
  fail "curl is not available"
fi

if getent ahosts packages.wazuh.com >/dev/null 2>&1; then
  pass "packages.wazuh.com resolves"
else
  fail "packages.wazuh.com does not resolve"
fi

if command -v curl >/dev/null 2>&1 &&
   curl -fsSI --max-time 10 https://packages.wazuh.com/4.14/wazuh-install.sh >/dev/null; then
  pass "official Wazuh 4.14 installation assistant is reachable over HTTPS"
else
  fail "official Wazuh 4.14 installation assistant is not reachable over HTTPS"
fi

echo
if (( failures == 0 )); then
  echo "RESULT: PASS"
  echo "SOC-MGMT-01 is ready for the controlled Wazuh central installation."
  exit 0
fi

echo "RESULT: FAIL ($failures issue(s))" >&2
exit 1
