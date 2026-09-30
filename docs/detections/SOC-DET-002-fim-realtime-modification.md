# SOC-DET-002 — Realtime file integrity modification

Status: Validated  
Change: CHG-010  
Asset: `SOC-ENDPOINT-01`

## Detection objective

Validate the complete File Integrity Monitoring path for one controlled modification in a dedicated lab directory:

```text
authorized file modification
  -> Linux realtime filesystem notification
  -> Wazuh FIM / syscheck
  -> Wazuh Agent 001
  -> TCP/1514
  -> Wazuh manager
  -> integrity rule evaluation
  -> alert
  -> analyst triage
```

The dedicated path avoids enabling realtime monitoring broadly across system directories merely to generate portfolio evidence.

## Test boundary

The endpoint monitored:

```text
/opt/mini-soc/fim-test
```

with realtime FIM enabled. The controlled file was:

```text
/opt/mini-soc/fim-test/controlled.conf
```

After configuration validation and one agent restart to activate the realtime directory, the accepted test modified the file without restarting Wazuh. The final controlled content was `mini-soc-fim-baseline-v3`.

## Detection result

Primary alert:

```text
Rule: 550
Level: 7
Description: Integrity checksum changed.
Mode: realtime
Event: modified
Changed attributes:
  mtime
  md5
  sha1
  sha256
MITRE ATT&CK:
  T1565.001 — Stored Data Manipulation
Tactic:
  Impact
Agent:
  001 / SOC-ENDPOINT-01
```

Wazuh retained before/after integrity values for the changed hashes. Exact hash values are intentionally not required in the public case record; the important evidence is that the manager received and correlated the before/after integrity state for the controlled modification.

## Triage

**Validation:** True Positive. The file was intentionally modified on the endpoint and Wazuh independently emitted the corresponding realtime integrity alert.

**Scope:** one controlled file modification in a dedicated test directory on one lab endpoint.

**Analysis:** rule 550 correctly identified an integrity checksum change. The ATT&CK mapping provides useful adversary context, but a checksum change alone does not establish malicious data manipulation, compromise or attacker intent.

**Disposition:** `True Positive — Authorized Security Test / Benign`.

The disposition is an analyst conclusion for the authorized exercise, not an automatic Wazuh determination.

**Response:** no containment was required. The test produced the expected telemetry and no unauthorized activity was established.

## Telemetry availability finding

An earlier modification was not accepted as detection evidence because the endpoint-to-manager telemetry path was unavailable during the test window.

Troubleshooting was performed before changing Wazuh identity or FIM configuration. A single local agent process and service were confirmed, then the path was tested through socket state, TCP reachability, IP reachability and neighbor resolution. The failure was isolated to stale VirtualBox bridged-adapter bindings after the physical hosts changed which Ethernet/Wi-Fi adapters carried their LAN connectivity.

The VM bridge bindings were corrected to the active physical adapters. L3 reachability and TCP/1514 were revalidated, and the existing `wazuh-agentd` session recovered to an established state without reenrollment, key replacement or an agent restart. Only then was the controlled FIM modification repeated and accepted as SOC-DET-002.

This operational finding is recorded because detection confidence depends on telemetry availability. It does not convert CHG-010 into a network redesign.

## Evidence handling

Raw `alerts.json`, private addressing, MAC addresses, credentials and agent keys remain outside the public repository. Public evidence retains only the fields needed to establish detection semantics, provenance, ATT&CK context, scope and analyst disposition.

## Reproduction

1. Confirm Agent 001 is active and its TCP/1514 telemetry session is healthy.
2. Confirm the dedicated FIM directory is configured for realtime monitoring.
3. Validate Wazuh configuration before testing.
4. Modify the controlled file once without restarting the agent.
5. Confirm Wazuh emits rule 550 for `SOC-ENDPOINT-01` with `mode: realtime` and `event: modified`.
6. Compare the monitored path and changed integrity attributes with the authorized action.
7. Record the analyst disposition and avoid inferring malicious intent from the integrity alert alone.

## Portfolio significance

SOC-DET-002 demonstrates integrity monitoring, realtime telemetry, cryptographic change evidence, ATT&CK contextualization and analyst triage. The interrupted first attempt also demonstrates that telemetry availability is part of detection assurance: an alert is only defensible when the collection and transport path is known to be healthy.
