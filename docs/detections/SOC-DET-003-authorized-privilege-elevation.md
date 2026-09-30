# SOC-DET-003 — Authorized privilege elevation with su

Status: Validated  
Change: CHG-011  
Asset: `SOC-ENDPOINT-01`

## Detection objective

Validate whether an authorized transition from the normal operating account to `root` is collected and represented by Wazuh with enough context for an analyst to distinguish privileged activity from a confirmed security incident.

The controlled sequence was:

```text
socops
  -> su -
  -> successful root session
  -> exit
  -> socops
```

No failed authentication attempts were introduced.

## Detection result

The accepted session-open event was:

```text
Rule: 5501
Level: 3
Description: PAM: Login session opened.
Program: su
Source user: socops
Target user: root
Source UID: 1000
Source: journald
Agent: 001 / SOC-ENDPOINT-01
MITRE ATT&CK:
  T1078 — Valid Accounts
Tactics include:
  Privilege Escalation
```

The corresponding session close was recorded by Rule 5502, level 3, `PAM: Login session closed.`.

The open/close sequence establishes that the privileged session was observed across its lifecycle.

## Triage

**Validation:** True Positive. A real privilege transition occurred and Wazuh correctly collected the PAM session event.

**Scope:** one authorized `su -` transition from `socops` to `root` on one lab endpoint, followed immediately by session exit.

**Analysis:** the event contains useful identity context: the originating account was `socops`, the target was `root`, and the originating UID was 1000. Wazuh maps Rule 5501 to ATT&CK T1078 Valid Accounts and includes Privilege Escalation among its tactics.

That ATT&CK context is not proof that an attacker escalated privileges. The same operating-system behavior can occur during legitimate administration. Analyst context and authorization therefore remain necessary.

**Disposition:** `True Positive — Authorized Administrative Activity / Benign`.

**Response:** no containment was required.

## Analyst lesson

This case demonstrates an important SOC distinction:

- **event truth:** a privileged root session was opened;
- **detection truth:** Wazuh emitted a valid PAM session alert;
- **ATT&CK context:** the behavior can be relevant to Valid Accounts / Privilege Escalation;
- **incident conclusion:** malicious intent or compromise was not established.

A SOC analyst should not collapse these four layers into a single conclusion.

## Evidence boundary

Raw `alerts.json`, private IP addresses, credentials, agent keys and unrelated historical alerts remain outside the public repository.

A separate earlier `su` event had different UID context and was deliberately excluded from SOC-DET-003. The accepted event is the controlled sequence whose source UID identifies the unprivileged `socops` context.

## Reproduction

1. Confirm Agent 001 is active and telemetry is healthy.
2. Start from an authenticated `socops` shell.
3. Execute one authorized `su -` and authenticate successfully.
4. Do not execute privileged changes; exit the root session.
5. Confirm Rule 5501 identifies `socops` as source and `root` as target.
6. Confirm Rule 5502 records session closure.
7. Classify using the approved test context rather than treating the ATT&CK mapping as proof of malicious activity.

## Portfolio significance

SOC-DET-003 demonstrates identity-aware triage and analyst judgment. The value is not merely detecting `root`: it is preserving the distinction between telemetry, detection logic, ATT&CK contextualization and an evidence-based incident disposition.
