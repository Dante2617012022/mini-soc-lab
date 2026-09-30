# Wazuh endpoint deployment and enrollment

Change: CHG-009

## Objective

Record the controlled Wazuh Agent deployment on `SOC-ENDPOINT-01` and the validated trust path to the Wazuh manager after CHG-008 established network connectivity.

## Version alignment

The manager reported Wazuh `v4.14.8`. The endpoint repository offered `wazuh-agent 4.14.8-1`, which was selected deliberately to avoid introducing a manager/agent version mismatch during the first enrollment.

The endpoint is Debian 13 (amd64). Installation used the official Wazuh 4.x package repository and configured the manager address only at runtime. Private addressing is not committed as stable configuration.

## Enrollment result

After installation, the agent configuration used:

- manager communication over TCP/1514;
- automatic enrollment through the manager enrollment service on TCP/1515;
- agent name `SOC-ENDPOINT-01`.

The first controlled start returned a valid enrollment key. Manager-side verification then showed:

```text
Agent ID: 001
Name: SOC-ENDPOINT-01
Status: Active
```

This proves the enrollment identity and active manager communication without publishing the agent key or raw enrollment material.

## Operational control

The endpoint package was placed on an APT hold after validating `4.14.8-1`. The hold is a temporary lab change-control measure to prevent accidental version drift; it is not a patch-management strategy and must be revisited when the manager version changes.

No Wazuh API or dashboard exposure is required for agent communication.

## Telemetry observed after enrollment

The agent started its expected modules, including log collection, file-integrity monitoring, system inventory and Security Configuration Assessment. Debian authentication events are collected from journald.

SCA findings are treated as a separate risk-based hardening workstream. A benchmark failure count is not, by itself, authorization to change the endpoint baseline.

## Rollback boundary

If agent deployment must be reversed, stop/disable the agent and remove only the Wazuh Agent package/configuration after preserving any evidence required for the current investigation. Network rollback remains governed by CHG-008.

Do not remove the Wazuh manager, alter SSH hardening, or change unrelated endpoint services as part of agent rollback.

## Acceptance

Deployment/enrollment is accepted because the selected agent version aligned with the manager, enrollment returned a valid key, Agent ID 001 became Active, and subsequent endpoint telemetry reached the manager.
