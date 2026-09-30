# Wazuh cross-host connectivity

Change: CHG-008

## Objective

Provide the minimum network path required for `SOC-ENDPOINT-01` to reach the Wazuh manager on `SOC-MGMT-01` across two physical Windows hypervisors, while preserving the existing NAT path as the default route for each VM.

## Decision record

The initial design proposed Windows-host VirtualBox NAT forwards for TCP/1514 and TCP/1515. Read-only discovery showed both physical hosts are already on the same trusted LAN. The implemented design therefore uses a second VirtualBox adapter in bridged mode on each VM instead of creating Windows port forwards or additional Windows Firewall rules.

This is a deliberate design change based on UAT, not an undocumented deviation. It avoids host-level Wazuh forwarding rules and gives the two lab VMs a direct, dedicated lab path. The trade-off is that each VM now has a presence on the trusted LAN, so exposure must remain limited to required services and the bridged path must not become the default route.

## Implemented topology

```text
SOC-ENDPOINT-01
  NIC1: VirtualBox NAT ---- default route / existing loopback-only SSH administration
  NIC2: bridged -----------+
                           |
                     trusted lab LAN
                           |
  NIC2: bridged -----------+
SOC-MGMT-01
  NIC1: VirtualBox NAT ---- default route / existing management path
```

Private DHCP addresses are runtime evidence and are intentionally not treated as repository configuration or stable identifiers.

## Routing and exposure contract

- NIC1 remains the default route on both VMs.
- NIC2 is used for direct lab connectivity between the endpoint and manager.
- `SOC-ENDPOINT-01` explicitly suppresses a default gateway learned on the bridged interface.
- `SOC-MGMT-01` accepts DHCP on the bridged interface without installing its routes as the default path.
- Wazuh TCP/1514 is used for agent communication.
- Wazuh TCP/1515 is used for enrollment.
- No CHG-008 Windows NAT forwards or Windows Firewall allow rules were created.
- CHG-008 does not expose the Wazuh API, indexer, or dashboard through new host-level forwards.
- Existing loopback-only SSH administration forwards remain unchanged.

## Read-only discovery

The repository helper remains useful for inventorying the Windows hypervisors and testing the selected manager address without changing configuration:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\management\check-wazuh-cross-host-network.ps1 -Role ManagerHost
```

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\management\check-wazuh-cross-host-network.ps1 `
  -Role EndpointHost `
  -ManagerAddress '<manager-VM-bridged-IPv4>'
```

Raw interface addresses and other host-specific evidence remain private.

## UAT evidence

UAT established the following facts on the real lab:

- both VMs retained their NAT interface and default route;
- both VMs obtained a second private IPv4 address through the bridged adapter;
- endpoint-to-manager layer-3 reachability was established;
- `SOC-MGMT-01` was listening on TCP/1514 and TCP/1515;
- `SOC-ENDPOINT-01` successfully established TCP connections to both Wazuh ports;
- no additional Windows host forwarding rule was required.

Agent installation, enrollment, detection content, and triage evidence are separate lifecycle concerns and should be formalized in the next change rather than expanding CHG-008.

## Rollback

Rollback is limited to the second bridged adapter and its guest configuration:

1. disable or remove NIC2 from each VM in VirtualBox;
2. remove only the CHG-008 guest configuration for the second interface;
3. verify NIC1 still owns the default route and existing loopback-only SSH administration still works.

Do not remove or broaden unrelated Windows Firewall policy, do not alter the existing SSH NAT forward, and do not change Wazuh central services as part of network rollback.

## Acceptance

CHG-008 is accepted when:

- both VMs preserve NAT as their default route;
- the bridged interface provides the dedicated cross-host lab path;
- the endpoint can reach the manager on TCP/1514 and TCP/1515;
- no unnecessary Wazuh management service is exposed by this change;
- rollback is bounded to NIC2 and its guest network configuration.

These conditions were validated during real-host UAT.
