# SOC-MGMT-01 Wazuh central installation

Change: CHG-007

## Objective

Install and validate the Wazuh all-in-one central stack on the accepted `SOC-MGMT-01` Ubuntu 24.04 LTS baseline without exposing management services to another physical host.

This change installs only the central Wazuh components:

- Wazuh indexer;
- Wazuh server/manager and Filebeat;
- Wazuh dashboard.

The Wazuh Agent on `SOC-ENDPOINT-01`, cross-host routing and detection use cases remain separate changes.

## Current vendor baseline

The Wazuh Quickstart currently supports Ubuntu 24.04 and documents the all-in-one installation assistant on the 4.14 release line:

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

Official references:

- https://documentation.wazuh.com/current/quickstart.html
- https://documentation.wazuh.com/current/getting-started/architecture.html

The lab does not pipe downloaded code directly into a privileged shell. The assistant is downloaded first, hashed and syntax-checked before execution.

## Preconditions

Before installation:

1. `BASELINE-MGMT-READY` must exist on the VirtualBox host.
2. `SOC-MGMT-01` must still use NAT-only networking.
3. The host-side SSH forwarding rule must remain loopback-bound.
4. No Wazuh central package or Wazuh APT source may already exist.
5. The VM must have the accepted 4 vCPU / 8 GiB / 50 GiB profile and healthy time synchronization.

Run the read-only gate:

```bash
bash scripts/management/check-wazuh-central-preflight.sh
```

Do not continue unless it returns `RESULT: PASS`.

## Installation directory and secret handling

Run the installation from a root-only directory so the generated credential archive is not created in a normal user's home:

```bash
sudo install -d -m 700 /root/wazuh-install
sudo curl -fsSL \
  https://packages.wazuh.com/4.14/wazuh-install.sh \
  -o /root/wazuh-install/wazuh-install.sh
```

Record the assistant hash and validate Bash syntax:

```bash
sudo sha256sum /root/wazuh-install/wazuh-install.sh
sudo bash -n /root/wazuh-install/wazuh-install.sh
```

The SHA-256 is execution evidence, not an authenticity substitute. Trust still depends on the official Wazuh HTTPS distribution channel.

Execute the all-in-one assistant from the protected directory:

```bash
sudo bash -c 'cd /root/wazuh-install && bash ./wazuh-install.sh -a'
```

The assistant generates random credentials and creates `wazuh-install-files.tar` in its working directory. Treat that archive and any extracted password file as secrets. Never commit, paste into public evidence, or copy them into the repository.

The repository ignores and CI rejects the common generated Wazuh credential artifacts as a defense-in-depth control.

## Central health validation

After installation, validate service state:

```bash
sudo systemctl is-active wazuh-manager
sudo systemctl is-active wazuh-indexer
sudo systemctl is-active wazuh-dashboard
sudo systemctl is-active filebeat
systemctl --failed
systemctl is-system-running
```

Review package versions:

```bash
sudo dpkg-query -W \
  wazuh-manager wazuh-indexer wazuh-dashboard filebeat
```

Review central listeners without publishing the complete raw output:

```bash
sudo ss -ltnp
```

Expected central ports relevant to this lab include:

| Purpose | Default |
| --- | --- |
| Dashboard HTTPS | TCP/443 |
| Agent communication | TCP/1514 |
| Agent enrollment | TCP/1515 |
| Wazuh server API | TCP/55000 |
| Indexer API | TCP/9200 |

The existence of a guest listener does not by itself expose the service to the physical LAN while VirtualBox remains NAT-only.

Official references:

- https://documentation.wazuh.com/current/getting-started/architecture.html
- https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/requirements.html

## Dashboard UAT from the Windows host

Do not bridge the VM for dashboard access.

With the VM running, first ensure Windows host port 8443 is free, then create a loopback-only NAT forwarding rule:

```powershell
$VBox = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$VM = "SOC-MGMT-01"

Get-NetTCPConnection -State Listen -LocalPort 8443 -ErrorAction SilentlyContinue

& $VBox controlvm $VM natpf1 `
  "wazuh-dashboard-loopback,tcp,127.0.0.1,8443,,443"

Test-NetConnection 127.0.0.1 -Port 8443
```

The dashboard is then reached from the same Windows host at `https://127.0.0.1:8443`.

The Wazuh quickstart documents that the initial dashboard certificate is self-signed, so a browser trust warning is expected. Do not publish the generated admin password.

The password can be retrieved locally from the protected archive when needed:

```bash
sudo tar -O -xvf \
  /root/wazuh-install/wazuh-install-files.tar \
  wazuh-install-files/wazuh-passwords.txt
```

Keep the output private.

## Disable accidental Wazuh upgrades

Wazuh recommends disabling its package repository after the central installation is complete to prevent accidental upgrades that can break the environment.

For this Ubuntu VM:

```bash
sudo sed -i 's/^deb /#deb /' /etc/apt/sources.list.d/wazuh.list
sudo apt update
```

Verify that no active Wazuh `deb` line remains before accepting the change.

Official reference:

- https://documentation.wazuh.com/current/quickstart.html

A future Wazuh upgrade must be a separate, reviewed change with backup, compatibility and rollback checks.

## Acceptance

CHG-007 is accepted only when:

1. preflight passes;
2. installation completes without unresolved errors;
3. manager, indexer, dashboard and Filebeat are active;
4. no failed systemd units remain;
5. central listeners are reviewed;
6. dashboard login works through host loopback only;
7. the Wazuh package repository is disabled;
8. generated credential material remains private;
9. the VM shuts down cleanly;
10. a powered-off snapshot named `WAZUH-CENTRAL-READY` is created.

## Rollback

If installation or validation fails, power off the VM and restore the existing VirtualBox snapshot:

`BASELINE-MGMT-READY`

Do not attempt repeated partial repairs on an unknown central-stack state when a known-good rollback point exists.
