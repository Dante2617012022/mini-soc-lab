# Wazuh cross-host connectivity

Change: CHG-008

## Objective

Create the minimum network path required for `SOC-ENDPOINT-01` to reach the Wazuh manager on `SOC-MGMT-01` while preserving VirtualBox NAT isolation on both VMs.

## Current constraint

`SOC-ENDPOINT-01` and `SOC-MGMT-01` run on different physical Windows hypervisors. VirtualBox host-only and internal networks do not span separate physical hosts, so the endpoint cannot reach the manager through those network types.

The preferred path for this phase is:

```text
SOC-ENDPOINT-01 (VirtualBox NAT)
        |
        | outbound TCP/1514 + TCP/1515
        v
Windows endpoint host
        |
        | trusted physical LAN
        v
Windows manager host
        |
        | VirtualBox NAT port-forward
        v
SOC-MGMT-01 :1514 / :1515
```

Do not use bridged networking unless a later design review shows that the scoped NAT-forward approach cannot satisfy the requirement.

## Wazuh connectivity contract

Current Wazuh enrollment documentation identifies:

- TCP/1514 for agent communication;
- TCP/1515 for enrollment via automatic agent request;
- TCP/55000 only when enrollment uses the Wazuh server API.

CHG-008 uses TCP/1514 and TCP/1515 only. TCP/443, TCP/55000 and TCP/9200 remain unexposed.

Official references:

- https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/requirements.html
- https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/troubleshooting.html

## Read-only discovery

Run the repository helper separately on both Windows hypervisors and keep the resulting private IPv4 information out of Git:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\management\check-wazuh-cross-host-network.ps1 -Role ManagerHost
```

and:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\management\check-wazuh-cross-host-network.ps1 -Role EndpointHost
```

Select one active IPv4 interface per host only after confirming both addresses belong to the intended trusted LAN/routing domain.

## Manager-host exposure design

Before mutation, confirm host TCP/1514 and TCP/1515 are unused.

With `SOC-MGMT-01` running, create VirtualBox NAT forwards bound to the selected manager-host LAN IPv4 address. Do not bind to `0.0.0.0`.

```powershell
$ManagerHostIPv4 = '<manager-host-LAN-IPv4>'
$EndpointHostIPv4 = '<endpoint-host-LAN-IPv4>'
$VBox = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
$VM = 'SOC-MGMT-01'

& $VBox controlvm $VM natpf1 `
  "wazuh-agent-1514,tcp,$ManagerHostIPv4,1514,,1514"

& $VBox controlvm $VM natpf1 `
  "wazuh-enroll-1515,tcp,$ManagerHostIPv4,1515,,1515"
```

Create Windows Firewall allow rules limited to the selected endpoint-host source address:

```powershell
New-NetFirewallRule `
  -DisplayName 'MiniSOC Wazuh agent 1514 from endpoint host' `
  -Direction Inbound -Action Allow -Protocol TCP `
  -LocalAddress $ManagerHostIPv4 -LocalPort 1514 `
  -RemoteAddress $EndpointHostIPv4

New-NetFirewallRule `
  -DisplayName 'MiniSOC Wazuh enrollment 1515 from endpoint host' `
  -Direction Inbound -Action Allow -Protocol TCP `
  -LocalAddress $ManagerHostIPv4 -LocalPort 1515 `
  -RemoteAddress $EndpointHostIPv4
```

Do not create rules for the dashboard, indexer or Wazuh API.

## Connectivity validation

From the endpoint Windows host:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\management\check-wazuh-cross-host-network.ps1 `
  -Role EndpointHost `
  -ManagerAddress '<manager-host-LAN-IPv4>'
```

Then validate from `SOC-ENDPOINT-01` itself. The endpoint VM must be able to establish TCP connections to the selected manager-host address on 1514 and 1515 before the Wazuh Agent is installed.

## Rollback

Remove the VirtualBox forwards while `SOC-MGMT-01` is running:

```powershell
& $VBox controlvm $VM natpf1 delete 'wazuh-agent-1514'
& $VBox controlvm $VM natpf1 delete 'wazuh-enroll-1515'
```

Remove only the two CHG-008 Windows Firewall rules:

```powershell
Remove-NetFirewallRule -DisplayName 'MiniSOC Wazuh agent 1514 from endpoint host'
Remove-NetFirewallRule -DisplayName 'MiniSOC Wazuh enrollment 1515 from endpoint host'
```

Rollback must not alter the existing loopback-only SSH rule or any unrelated Windows Firewall policy.

## Acceptance

CHG-008 is accepted when the endpoint side can reach TCP/1514 and TCP/1515 through the scoped path, no additional Wazuh service is exposed, and the rollback commands are documented and validated.
