# SOC-ENDPOINT-01 telemetry contract

Change: CHG-004

## Purpose

Validate the endpoint telemetry required by the first Mini-SOC use cases before installing or enrolling the Wazuh Agent.

The endpoint operating system remains the authoritative source of the underlying events. Wazuh will collect, analyze and correlate those events later; it should not be treated as proof that an event existed if the endpoint itself never produced it.

## Current source

SOC-ENDPOINT-01 uses persistent systemd-journald storage established in CHG-003.

The first telemetry contract is:

| Use case | Endpoint source | Validation before Wazuh |
| --- | --- | --- |
| Failed SSH authentication | `ssh.service` / sshd journal events | Controlled incorrect password attempt |
| Successful SSH authentication | `ssh.service` / sshd journal events | Normal `socops` login |
| Privilege elevation | `su` / PAM journal events | Approved `su -` administrative session |
| Event ordering | system clock + journal timestamps | NTP synchronized |
| Persistence | `/var/log/journal` | Prior boots remain queryable |
| File Integrity Monitoring | Wazuh Syscheck (later) | Not applicable until agent deployment |

A single failed password is an authentication-failure event, not a brute-force finding. The later password-guessing detection will require repeated controlled failures and correlation, and will be mapped to MITRE ATT&CK T1110.001 only when the observed behavior satisfies that use case.

## Wazuh collection decision

Current Wazuh documentation states that the Linux agent Logcollector can read systemd-journald and that journald collection is enabled by default in the agent configuration.

For the MVP, do not add a custom journald filter before enrollment. Keeping the default journal source avoids prematurely excluding privilege or authentication events that we have not yet observed end-to-end.

Filtering can be introduced later if actual event volume demonstrates a noise or capacity problem.

## Future connectivity contract

When SOC-MGMT-01 exists:

- agent event communication requires manager TCP/1514 by default;
- automatic agent enrollment uses TCP/1515 by default;
- TCP/55000 is relevant only if the Wazuh server API is used for enrollment/management.

No manager port is opened or exposed as part of CHG-004.

## Controlled validation procedure

1. Keep one working SSH session open.
2. From a second Windows PowerShell terminal, make one intentionally incorrect password attempt for `socops`, then abort.
3. Connect normally with the correct password.
4. In the endpoint, perform one approved `su -` authentication and exit.
5. Collect the local evidence window:

```bash
su -c 'cd /home/socops/mini-soc-lab && bash scripts/endpoint/collect-telemetry-sample.sh --since "15 minutes ago"'
```

6. Validate the generated checksum:

```bash
su -c 'sha256sum -c /root/soc-evidence/telemetry/*.sha256'
```

Because `su -c` uses root's home directory, the default report path for this procedure is `/root/soc-evidence/telemetry`.

## Evidence handling

The telemetry report is private raw evidence. It can contain usernames, source addresses, timestamps, hostnames and authentication details.

Do not commit the report. Public evidence should later contain only sanitized excerpts and the derived finding.

## Rollback

No system configuration is changed by this validation. The controlled authentication events remain in the persistent journal as audit evidence and expire according to the bounded journald retention policy from CHG-003.
