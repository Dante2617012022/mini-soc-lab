# SOC-DET-004 — Controlled UDP Rate Anomaly

## Status

**Operationally validated in the controlled lab on 2026-10-07.**

CHG-025 remains detection-only. No automatic response is authorized for this detection.

## Detection objective

Identify a short, authorized UDP rate anomaly from the disposable workload `SOC-TEST-01` to a dedicated unused port on the Mini-SOC gateway.

## Data path

`SOC-TEST-01 (10.77.0.10) -> SOC-GW-01 (10.77.0.1:65000/UDP) -> Suricata -> EVE JSON -> Wazuh Agent -> Wazuh Manager/Indexer -> Dashboard`

## Signature

- engine: Suricata;
- SID: `1000002`;
- message: `MINI-SOC Controlled UDP Rate Anomaly`;
- source: `10.77.0.10`;
- destination: `10.77.0.1:65000/UDP`;
- threshold: 20 matches in 1 second, tracked by source;
- threshold mode: `type threshold`;
- action: alert only.

Canonical rule source:

`config/gateway/suricata/mini-soc-local.rules`

## Design isolation

The first draft used ICMP Echo Request traffic. Pre-UAT review identified that the same traffic would also match existing SID `1000001`, the intentional trigger for CHG-021 Active Response.

The final detection therefore uses a dedicated UDP test path. This preserves the semantic integrity of SID `1000001`, avoids Wazuh rule `100021`, and keeps CHG-025 detection-only.

## Validated UAT

Negative baseline:

- five low-rate UDP packets were transmitted;
- no SID `1000002` event appeared;
- no new SID `1000001` event appeared;
- no new Active Response occurred;
- the runtime blocking set remained empty.

Positive case:

- exactly thirty bounded UDP packets were transmitted;
- Suricata emitted SID `1000002`;
- the event matched `10.77.0.10 -> 10.77.0.1:65000/UDP`;
- action remained `allowed`;
- no new SID `1000001` appeared;
- no Active Response was triggered.

Both cases passed. Exact reproducible test commands and runtime validation are recorded in `docs/CHG-025.md`.

## Wazuh visibility

Threat Hunting confirmed the event on agent `SOC-GW-01` from `/var/log/suricata/eve.json`.

Wazuh exposed:

- `data.alert.signature_id = 1000002`;
- `data.alert.signature = MINI-SOC Controlled UDP Rate Anomaly`;
- protocol UDP;
- destination port `65000`;
- native Suricata rule `86601`;
- level `3`.

## Analyst disposition

**True Positive — Authorized Security Test / Benign**

The defined rate condition occurred and was correctly detected. The event does not by itself establish hostile intent or service impact.

- escalation: no;
- containment: no;
- automated response: no;
- ATT&CK: no mapping assigned without adversary context.

## Response boundary

Existing CHG-021 containment remains independently scoped to SID `1000001` through Wazuh rule `100021`.

CHG-025 does not modify nftables policy, Wazuh manager rules or Active Response configuration.

## False-positive considerations

The threshold is lab-specific. Production adoption would require workload baselining, service context, threshold tuning, alert-volume testing and availability requirements.

## Evidence and privacy

The repository records sanitized validation facts only. Raw PCAP, full EVE logs, credentials, private telemetry and unrelated network data are not published.

See `docs/CHG-025.md` for the complete change record, rollback and operational observations.
