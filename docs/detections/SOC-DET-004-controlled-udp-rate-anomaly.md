# SOC-DET-004 — Controlled UDP Rate Anomaly

## Status

**Pre-UAT.** The rule is CI-validated but is not operationally validated until CHG-025 UAT completes.

## Detection objective

Identify a short burst of UDP packets from the authorized disposable workload `SOC-TEST-01` to a dedicated unused UDP port on the Mini-SOC gateway at a rate above the lab baseline.

## Data path

`SOC-TEST-01 (10.77.0.10) -> SOC-GW-01 (10.77.0.1:65000/UDP) -> Suricata -> EVE JSON -> Wazuh -> Dashboard`

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

The dedicated UDP test path avoids matching existing ICMP SID `1000001`. That preserves CHG-021's independently governed Active Response path and keeps CHG-025 detection-only.

## Positive condition

```bash
sudo hping3 --udp -p 65000 -c 30 -i u20000 10.77.0.1
```

## Negative condition

```bash
sudo hping3 --udp -p 65000 -c 5 -i u1000000 10.77.0.1
```

The negative test must not produce SID `1000002`.

## Expected triage

**True Positive — Authorized Security Test / Benign**

The alert confirms that the defined rate condition occurred. It does not prove malicious intent or denial-of-service impact.

## Response

No automated response is authorized in CHG-025. Existing CHG-021 containment remains scoped to SID `1000001` through Wazuh rule `100021`.

## ATT&CK

No ATT&CK technique is assigned solely for portfolio appearance.

## False-positive considerations

The threshold is lab-specific. Production adoption would require workload baselining, alert-volume testing, service context and availability requirements.

## Evidence requirements

After UAT, retain sanitized evidence of the negative test, positive SID `1000002` event, Wazuh visibility, analyst disposition and service-health regression checks.

Do not publish raw PCAP, credentials, private telemetry or unrelated network data.
