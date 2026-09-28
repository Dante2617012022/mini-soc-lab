# SOC-ENDPOINT-01 Wazuh Agent readiness

Change: CHG-006

## Purpose

Prepare SOC-ENDPOINT-01 for a controlled Wazuh Agent deployment without creating a partially configured agent while SOC-MGMT-01 is unavailable.

This change is intentionally read-only on the endpoint.

## Why the agent is not installed yet

Current Wazuh enrollment requirements state that successful enrollment requires an installed and running Wazuh manager, an installed and running agent, and outbound connectivity from the agent to the manager services.

The current lab does not yet have SOC-MGMT-01. Installing the agent now would add a privileged security component without an enrollment target and would make later troubleshooting less deterministic.

Wazuh also documents that compatibility is guaranteed when the manager version is greater than or equal to the agent version. The lab therefore selects and pins the agent version only after the central stack version is known.

Official references:

- https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/requirements.html
- https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html
- https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/troubleshooting.html

## Future connectivity contract

The default Wazuh manager ports relevant to this lab are:

| Purpose | Default |
| --- | --- |
| Agent event communication | TCP/1514 |
| Automatic agent enrollment | TCP/1515 |
| Wazuh server API enrollment/management | TCP/55000 |

TCP/55000 is not automatically required for the endpoint data path. It becomes relevant only if the selected enrollment/management flow uses the Wazuh server API.

No port is opened by CHG-006.

## Local readiness gate

Run as the normal `socops` account:

```bash
bash scripts/endpoint/check-wazuh-agent-readiness.sh
```

The script verifies:

- expected endpoint hostname;
- Debian OS family;
- SSH service health;
- journald health;
- system time synchronization;
- persistent journal directory;
- Wazuh Agent is not already installed;
- Wazuh APT repository is not already configured;
- APT tooling remains available.

It does not:

- install packages;
- change repositories;
- modify SSH;
- modify journald;
- change firewall rules;
- write evidence files;
- contact a future Wazuh manager.

## Deployment gate after SOC-MGMT-01 exists

Before installing the agent:

1. record the Wazuh manager version;
2. choose an agent version compatible with that manager;
3. verify endpoint-to-manager reachability for the selected enrollment flow;
4. use the official Wazuh repository and GPG key;
5. avoid placing enrollment secrets in Git;
6. validate the agent service and the manager-side registration;
7. validate an established agent communication channel on TCP/1514;
8. confirm the CHG-004 SSH and privilege events arrive at the manager before enabling additional detections.

## Rollback

CHG-006 makes no endpoint configuration changes.

The later agent deployment change must define package/service rollback separately because that future step changes the monitored host.
