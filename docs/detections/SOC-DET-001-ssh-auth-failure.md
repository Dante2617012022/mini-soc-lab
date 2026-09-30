# SOC-DET-001 — SSH authentication failure

Status: Validated  
Change: CHG-009  
Asset: `SOC-ENDPOINT-01`

## Detection objective

Validate the complete detection path for a real but controlled failed SSH password authentication:

```text
sshd event
  -> systemd journal
  -> Wazuh Agent 001
  -> TCP/1514
  -> Wazuh manager
  -> decoder/rule evaluation
  -> alert
  -> analyst triage
```

The test used one intentional failed password attempt in the authorized lab. It was not a brute-force exercise.

## Detection result

Primary alert:

```text
Rule: 5760
Level: 5
Description: sshd: authentication failed.
MITRE ATT&CK:
  T1110.001 — Password Guessing
  T1021.004 — SSH
Tactics:
  Credential Access
  Lateral Movement
Source: journald
Agent: 001 / SOC-ENDPOINT-01
```

A subsequent Wazuh rule 5762 (level 4) recorded the SSH connection reset.

The source address and ephemeral source port are intentionally omitted from public evidence because they are runtime network details and are not needed to reproduce or understand the detection.

## Triage

**Validation:** True Positive. The underlying authentication failure was intentionally generated and independently observed at the endpoint and manager.

**Scope:** one controlled failed authentication against the lab account on one endpoint.

**Analysis:** rule 5760 correctly detected the failed SSH authentication. Wazuh's ATT&CK mapping identifies Password Guessing and SSH, but a single failed password does not establish brute force, account compromise, lateral movement, or malicious intent.

**Disposition:** `True Positive — Authorized Security Test / Benign`.

The disposition is the analyst conclusion for this controlled exercise; it is not an automatic Wazuh determination.

**Response:** no containment was required. Monitoring remains appropriate.

## Evidence handling

Raw journal output and Wazuh `alerts.json` are kept outside the public repository. Public evidence records only the fields needed to establish provenance, rule behavior, ATT&CK mapping, scope and analyst disposition.

No credential, agent key, full raw log, MAC address or unnecessary private IP address is published.

## Reproduction

1. Confirm `SOC-ENDPOINT-01` is Active in the Wazuh manager.
2. Generate exactly one authorized failed SSH password authentication against the lab endpoint.
3. Confirm the failed authentication exists in the endpoint journal.
4. Confirm Wazuh emits rule 5760 for Agent 001.
5. Compare timestamp, account and event semantics across source and alert.
6. Record the test as authorized/benign; do not infer brute force from a single failure.

Repeated failures should only be introduced under a separately reviewed correlation test with bounded attempt counts.

## Portfolio significance

SOC-DET-001 demonstrates an end-to-end defensive workflow rather than tool installation alone: telemetry generation, collection, transport, decoding, detection, ATT&CK context, investigation, scope assessment and documented disposition.
