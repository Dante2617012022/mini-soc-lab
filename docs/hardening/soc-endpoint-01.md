# SOC-ENDPOINT-01 base hardening

Change: CHG-003

## Problem

The endpoint is intentionally minimal, but it now exposes an SSH daemon inside the guest and will become a security telemetry source. Before Wazuh deployment, the management and logging posture needs to be deterministic and reviewable.

## Pre-change review

The CHG-003 read-only review found:

- only `root` and `socops` have interactive shells;
- `socops` is not a member of `sudo` or `docker`;
- SSH password authentication is enabled for `socops`;
- SSH root password authentication is already blocked, but key-based root login remains possible by default;
- X11 forwarding is enabled by the Debian/OpenSSH default;
- SSH allows six authentication attempts per connection;
- journald uses default/automatic storage behavior;
- time synchronization is healthy;
- nftables has no active ruleset;
- no unexpected TCP listener was observed.

Raw host evidence remains local and is not committed.

## Approved minimal changes

### SSH

The repository drop-in:

`config/endpoint/sshd_config.d/60-mini-soc-hardening.conf`

makes the following decisions explicit:

- deny all direct SSH login as `root`;
- keep password authentication enabled for the controlled SSH password-guessing detection use case;
- keep public-key authentication available for a later migration;
- reduce authentication attempts per connection from six to three;
- disable X11, agent and TCP forwarding because the endpoint only requires an administrative shell;
- keep `LogLevel INFO`, which is sufficient for the initial authentication use case.

Password authentication is not being disabled in this change because no alternate key-based administrative path has been accepted yet and the lab explicitly needs controlled password-failure telemetry.

### Journald

The repository drop-in:

`config/endpoint/journald.conf.d/60-mini-soc.conf`

sets:

- `Storage=persistent` so local security evidence survives reboot;
- `SystemMaxUse=256M` to bound log growth on the small endpoint disk.

### nftables

No endpoint firewall rules are added in CHG-003.

The current management path is already constrained by the VirtualBox NAT boundary and a Windows loopback-only port forward. Adding firewall policy before the later Wazuh cross-host network design would create lockout/rework risk without a demonstrated requirement.

The dedicated `SOC-GW-01` remains the planned location for firewall/NAT/segmentation policy.

### Accounts and groups

No account or group membership is changed. `socops` remains non-sudo and root remains the explicit local privilege-escalation path via `su -`.

## Application

First run the repository script in read-only mode:

```bash
bash scripts/endpoint/apply-base-hardening.sh --check
```

Apply only after review:

```bash
su -c 'cd /home/socops/mini-soc-lab && bash scripts/endpoint/apply-base-hardening.sh --apply'
```

The script validates the SSH source configuration before making changes and validates the effective SSH daemon configuration before reloading SSH.

## UAT

Keep the current SSH session open. From a second Windows PowerShell terminal, verify that a new management session succeeds through the approved local forward.

Then validate:

```bash
su -c '/usr/sbin/sshd -T' | grep -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries|x11forwarding|allowagentforwarding|allowtcpforwarding|loglevel)'
journalctl --list-boots
journalctl --disk-usage
timedatectl
ss -tuln
```

Expected SSH behavior:

```text
permitrootlogin no
passwordauthentication yes
pubkeyauthentication yes
maxauthtries 3
x11forwarding no
allowagentforwarding no
allowtcpforwarding no
loglevel INFO
```

After a reboot, `journalctl --list-boots` should still show the prior boot, demonstrating persistent journal storage.

## Rollback

Preferred rollback: restore the VirtualBox snapshot `BASELINE-ADMIN-READY`.

If snapshot restoration is unnecessary, remove only the CHG-003 drop-ins, validate SSH, reload SSH and restart journald. Do not delete `/var/log/journal`; retained logs are evidence, not configuration.
