# SOC-ENDPOINT-01 provisioning runbook

Change: CHG-002

## Approved VM profile

- Hypervisor: Oracle VirtualBox on the Dante Windows host
- VM name: `SOC-ENDPOINT-01`
- Guest OS: Debian 13 (trixie), 64-bit
- vCPU: 2
- RAM: 2048 MiB
- Disk: 20 GiB VDI, dynamically allocated
- Initial network: NAT only
- Purpose: dedicated Linux endpoint telemetry source for the Mini-SOC

The existing general-purpose Debian VM remains untouched.

## Security intent

This VM is intentionally smaller and cleaner than the existing Debian workstation. It should not include Docker, development stacks, printing/discovery services or other components unless a later requirement justifies them.

The endpoint role is limited to:

- operating-system and authentication telemetry;
- Wazuh Agent;
- File Integrity Monitoring;
- sudo / privileged-account events;
- YARA in a later phase;
- controlled security test generation.

## Installation guidance

Use the Debian installer with the minimum package set required to obtain a stable command-line system.

Preferred package selection:

- Standard system utilities
- SSH server: leave disabled during the installer phase.

Do not select a desktop environment for this VM.

## Accounts

Use a unique lab password that is not reused from personal or production systems.

The provisioning step should create:

- a normal operating user named `socops`;
- an explicit root administrative path for approved system changes.

`socops` remains outside the `sudo` and `docker` groups unless a later change explicitly justifies additional privilege.

## Administrative bootstrap

After the minimal OS is verified, an SSH management path may be enabled as part of CHG-002 so the endpoint can remain headless.

Approved access pattern:

- install `openssh-server` from the Debian repositories;
- keep the VM adapter in VirtualBox NAT mode;
- expose guest TCP/22 only through a VirtualBox port-forward from Windows `127.0.0.1:2222`;
- retain SSH strict host-key verification;
- install `git` from the Debian repositories to retrieve the controlled lab repository.

This management path is not intended to expose SSH to the physical LAN.

## Post-install acceptance

Before Wazuh, YARA or other SOC/security tooling is installed:

1. boot Debian successfully;
2. verify CPU, RAM and disk allocation;
3. verify NAT connectivity and DNS;
4. verify that no desktop environment, Docker, printing or discovery stack is present;
5. establish and verify the approved localhost-only SSH management path;
6. install Git from the Debian repositories and clone this repository;
7. run `scripts/endpoint/collect-baseline.sh`;
8. validate the generated SHA-256;
9. review enabled/running services and privilege groups;
10. take a VirtualBox snapshot named `BASELINE-ADMIN-READY`.

The baseline output is raw operational evidence and must remain outside the public repository.

## Rollback

Restore `BASELINE-ADMIN-READY` or discard the new VM. Existing VMs are not part of this change.
