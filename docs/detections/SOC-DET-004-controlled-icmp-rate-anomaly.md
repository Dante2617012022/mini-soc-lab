# SOC-DET-004 — Controlled ICMP Rate Anomaly

## Status

**Pre-UAT.** The rule is defined and CI-validated before runtime activation. Do not describe this detection as operationally validated until CHG-025 UAT is completed.

## Detection objective

Identify a short burst of ICMP Echo Requests from the authorized disposable workload `SOC-TEST-01` to the Mini-SOC gateway at a rate above the lab baseline.

## Data path

`SOC-TEST-01 (10.77.0.10) -> SOC-GW-01 (10.77.0.1) -> Suricata -> EVE JSON -> Wazuh -> Dashboard`

## Signature

- engine: Suricata;
- SID: `1000002`;
- message: `MINI-SOC Controlled ICMP Rate Anomaly`;
- source: `10.77.0.10`;
- destination: `10.77.0.1`;
- ICMP type: Echo Request (`itype:8`);
- threshold: 20 matches in 1 second, tracked by source;
- action: alert only.

Canonical rule source:

`config/gateway/suricata/mini-soc-local.rules`

## Positive condition

A bounded authorized test must exceed the threshold without using an uncontrolled flood mode.

Planned UAT generator:

```bash
sudo hping3 --icmp -c 30 -i u20000 10.77.0.1
```

## Negative condition

Normal low-rate ICMP must not produce SID `1000002`.

Planned baseline:

```bash
ping -c 5 -i 1 10.77.0.1
```

## Expected triage

**True Positive — Authorized Security Test / Benign**

The alert confirms that the defined rate condition occurred. It does not by itself establish malicious intent or prove a denial-of-service impact.

## Response

No automated response is authorized in CHG-025. Existing CHG-021 containment remains independently scoped to SID `1000001` through Wazuh rule `100021`.

## ATT&CK

No ATT&CK technique is assigned solely to make the portfolio appear more complete. A mapping should be added only if a later scenario provides defensible adversary context.

## False-positive considerations

The threshold is lab-specific. Legitimate diagnostics or monitoring could exceed it in another environment. Production adoption would require baseline analysis, source/destination generalization review, alert-volume testing and availability requirements.

## Evidence requirements

After UAT, retain sanitized evidence of:

- negative test result;
- positive SID `1000002` event;
- Wazuh visibility;
- analyst disposition;
- service-health regression checks.

Do not publish raw PCAP, credentials, private telemetry or unrelated network data.
