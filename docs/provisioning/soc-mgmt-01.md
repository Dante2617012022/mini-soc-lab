# SOC-MGMT-01 provisioning runbook

Change: CHG-005

## Objective

Provision a clean, minimal Ubuntu Server virtual machine on the second Windows/VirtualBox host. This VM will later run the Wazuh central components, but CHG-005 stops before Wazuh installation.

Separating operating-system provisioning from the security platform installation gives the lab a clean rollback point and makes later troubleshooting attributable to the correct layer.

## Capacity gate

Before creating the VM, run the repository's read-only Windows host inventory:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\management\collect-windows-host-capacity.ps1
```

The inventory intentionally avoids printing IP addresses, MAC addresses, usernames and secrets. Review:

- Windows architecture;
- CPU cores / logical processors;
- hardware virtualization state;
- total RAM;
- free disk on the intended VirtualBox drive;
- active network adapters;
- VirtualBox availability and version.

Do not create the VM until the resource allocation is accepted.

## Target VM profile

Subject to the physical-host capacity gate:

- VM name: `SOC-MGMT-01`
- Hostname: `SOC-MGMT-01`
- Guest OS: Ubuntu Server 24.04 LTS, 64-bit
- vCPU: 4
- RAM: 8 GiB
- Disk: 50 GiB, dynamically allocated
- Initial network: VirtualBox NAT only
- Desktop environment: none
- Purpose: future single-node Wazuh server + indexer + dashboard

The current Wazuh Quickstart recommendation for an all-in-one deployment monitoring 1–25 agents is 4 vCPU, 8 GiB RAM and 50 GB storage. Ubuntu 24.04 is listed as a recommended operating system for the central components.

Official reference:

- https://documentation.wazuh.com/current/quickstart.html

The lab has far fewer than 25 agents, but the documented quickstart profile is retained as the starting target because the indexer and dashboard are the resource-heavy components. If the physical host cannot safely sustain that allocation, reduce scope or redesign rather than silently under-provisioning the VM.

## Installation boundary

CHG-005 installs only the base operating system and administrative prerequisites required for a stable headless VM.

Do not install in this change:

- Wazuh server;
- Wazuh indexer;
- Wazuh dashboard;
- Docker;
- a desktop environment;
- Suricata;
- YARA;
- unrelated development tooling.

## Network boundary

Use NAT during initial provisioning so package installation and time synchronization work without exposing the guest directly to the physical LAN.

Do not switch to bridged networking and do not open Wazuh ports during base provisioning.

The later cross-host design must explicitly decide how SOC-ENDPOINT-01 reaches SOC-MGMT-01. Current Wazuh documentation identifies the following configurable manager-side defaults relevant to enrollment and agent communication:

- TCP/1514 — agent communication;
- TCP/1515 — automatic agent enrollment;
- TCP/55000 — Wazuh server API, only if the selected enrollment/management flow requires it.

Official references:

- https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/requirements.html
- https://documentation.wazuh.com/current/getting-started/architecture.html

## Accounts

Use a unique lab password that is not reused from personal or production systems.

Create a dedicated non-root operator account during Ubuntu installation. Keep privilege elevation explicit and auditable through the Ubuntu administrative path.

Do not place credentials, generated Wazuh passwords or SSH private keys in Git.

## Base acceptance

Before Wazuh is installed:

1. verify the VM identity and allocated CPU, RAM and disk;
2. verify Ubuntu Server 24.04 LTS and architecture;
3. verify package repositories and DNS;
4. verify time synchronization;
5. review enabled/running services and listening ports;
6. verify the intended administrative access path;
7. confirm no GUI or unrelated services were installed;
8. clone the controlled Mini-SOC repository if Git is approved for the management VM;
9. collect a local baseline and SHA-256 using a management-specific collector added during this change if required;
10. create a VirtualBox snapshot named `BASELINE-MGMT-READY`.

The snapshot must be taken before the Wazuh installation change.

## Rollback

Before acceptance, delete the new VM if provisioning is rejected.

After acceptance, restore `BASELINE-MGMT-READY` if the later Wazuh central-stack installation fails or introduces an unacceptable configuration state.
