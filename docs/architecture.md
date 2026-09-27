# Architecture

## Purpose

The lab is designed to demonstrate a small but defensible Blue Team workflow: collect telemetry, detect, investigate, map behavior, decide on containment, validate the response, and preserve evidence.

## Trust boundaries

### Physical hosts

Windows hosts provide virtualization only. Security tooling should run inside dedicated VMs unless a later requirement explicitly justifies host instrumentation.

### SOC-ENDPOINT-01

Debian 13 endpoint used to produce controlled authentication, privilege, integrity and malware-detection telemetry.

Primary responsibility: **endpoint telemetry source**.

### SOC-MGMT-01

Ubuntu Server 24.04 LTS VM intended for the Wazuh all-in-one deployment.

Primary responsibility: **central collection, indexing, correlation, alerting and investigation**.

### SOC-GW-01

Dedicated gateway VM planned for a later phase.

Primary responsibilities:

- nftables firewalling, NAT and segmentation;
- Suricata network IDS;
- firewall and EVE JSON telemetry;
- scoped response enforcement after detections have been validated.

Suricata should only be described as observing traffic that actually traverses or is mirrored to its monitored interface.

### VirusTotal

External enrichment service. It is outside the lab trust boundary.

Initial integration should prefer SHA-256 reputation lookups. Private or confidential files must not be uploaded as part of the normal workflow.

## Initial data flow

```text
SOC-ENDPOINT-01
   │
   │ Wazuh agent telemetry
   ▼
SOC-MGMT-01
   │
   ├── detection
   ├── investigation
   ├── ATT&CK mapping
   └── evidence

Later:

lab traffic
   ▼
SOC-GW-01 / nftables / Suricata
   │
   ├── eve.json
   └── firewall logs
          │
          ▼
     SOC-MGMT-01

YARA/FIM finding
   │
   └── SHA-256 lookup ──► VirusTotal
                           │
                           └── enrichment context ──► analyst
```

## Architectural decisions

1. **Wazuh first, Graylog later only if justified.** A second log-management platform is not introduced until a concrete requirement exists.
2. **Suricata rather than parallel Snort + Suricata.** One NIDS reduces operational complexity while still demonstrating network detection.
3. **nftables rather than a physical MikroTik.** The lab reproduces firewall/NAT/segmentation capabilities in a Linux gateway VM.
4. **Detect before auto-blocking.** Active Response remains disabled until detection quality, false positives and rollback are tested.
5. **Evidence minimization.** Public artifacts must avoid secrets, credentials, unnecessary IPs, usernames and raw packet captures.

## Residual risks

- Consumer hardware limits capacity and redundancy.
- Two physical hypervisors complicate network visibility and routing.
- A lab cannot reproduce production-scale telemetry, availability or threat volume.
- External enrichment services introduce privacy and availability dependencies.
