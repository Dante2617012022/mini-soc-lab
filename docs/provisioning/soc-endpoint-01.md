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
- SSH server: leave disabled during the initial install unless the installer requires a decision; it will be enabled later through an explicit hardening change.

Do not select a desktop environment for this VM.

## Accounts

Use a unique lab password that is not reused from personal or production systems.

The provisioning step should create:

- a normal operating user;
- an explicit administrative path for approved system changes.

Privileged group membership will be documented in the post-install baseline. Do not use Docker-group membership or other privilege-equivalent workarounds.

## Post-install acceptance

Before Wazuh, YARA or other security tooling is installed:

1. boot Debian successfully;
2. verify CPU, RAM and disk allocation;
3. verify NAT connectivity and DNS;
4. take a VirtualBox snapshot named `BASELINE-CLEAN-INSTALL`;
5. clone this repository;
6. run `scripts/endpoint/collect-baseline.sh`;
7. validate the generated SHA-256;
8. review enabled/running services and privilege groups.

## Rollback

Delete the new VM or restore `BASELINE-CLEAN-INSTALL`. Existing VMs are not part of this change.
