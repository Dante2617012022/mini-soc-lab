#!/usr/bin/env bash
set -Eeuo pipefail

PATH="${PATH}:/usr/sbin:/sbin"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ssh_source="${repo_root}/config/endpoint/sshd_config.d/60-mini-soc-hardening.conf"
journal_source="${repo_root}/config/endpoint/journald.conf.d/60-mini-soc.conf"

ssh_target="/etc/ssh/sshd_config.d/60-mini-soc-hardening.conf"
journal_target="/etc/systemd/journald.conf.d/60-mini-soc.conf"

usage() {
  cat <<'EOF'
Usage: bash scripts/endpoint/apply-base-hardening.sh [--check|--apply]

--check  Validate prerequisites and source configuration without changing the host.
--apply  Install the approved SSH and journald drop-ins, validate sshd, then reload/restart services.

Run --apply as root. The script does not alter nftables, users/groups, or install packages.
Rollback for CHG-003 is the BASELINE-ADMIN-READY VirtualBox snapshot.
EOF
}

mode="--check"
if [[ $# -gt 1 ]]; then
  usage >&2
  exit 2
fi
if [[ $# -eq 1 ]]; then
  mode="$1"
fi

case "$mode" in
  --check|--apply) ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    echo "ERROR: unknown argument: $mode" >&2
    usage >&2
    exit 2
    ;;
esac

for file in "$ssh_source" "$journal_source"; do
  [[ -r "$file" ]] || { echo "ERROR: missing source file: $file" >&2; exit 1; }
done

command -v sshd >/dev/null 2>&1 || { echo "ERROR: sshd not found" >&2; exit 1; }
command -v ssh-keygen >/dev/null 2>&1 || { echo "ERROR: ssh-keygen not found" >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "ERROR: systemctl not found" >&2; exit 1; }

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
tmp_config="${tmp_dir}/sshd_config"
tmp_host_key="${tmp_dir}/ssh_host_ed25519_key"

ssh-keygen -q -t ed25519 -N '' -f "$tmp_host_key"

cat >"$tmp_config" <<EOF
HostKey $tmp_host_key
UsePAM no
Include $ssh_source
EOF

sshd -t -f "$tmp_config"

echo "Source SSH configuration syntax: OK"

if [[ "$mode" == "--check" ]]; then
  echo "Read-only validation complete."
  exit 0
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: --apply must be run as root" >&2
  exit 1
fi

install -d -m 0755 /etc/ssh/sshd_config.d
install -m 0644 "$ssh_source" "$ssh_target"

if ! sshd -t; then
  rm -f "$ssh_target"
  echo "ERROR: effective sshd configuration failed validation; drop-in removed." >&2
  exit 1
fi

install -d -m 0755 /etc/systemd/journald.conf.d
install -m 0644 "$journal_source" "$journal_target"
install -d -m 2755 -o root -g systemd-journal /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal

systemctl reload ssh
systemctl restart systemd-journald

echo "CHG-003 base hardening applied."
echo "Validate SSH from a second Windows terminal before closing the current session."
