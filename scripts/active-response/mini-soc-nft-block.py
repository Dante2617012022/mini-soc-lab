#!/usr/bin/python3
"""CHG-021: bounded nftables Active Response for SOC-TEST-01.

Stateful Wazuh Active Response. It accepts only the authorized lab source
10.77.0.10, manages only a dedicated runtime nftables table, and never
modifies /etc/nftables.conf or the persistent Mini-SOC gateway ruleset.
"""

import datetime
import ipaddress
import json
import subprocess
import sys

NFT = "/usr/sbin/nft"
LOG = "/var/ossec/logs/active-responses.log"
ALLOWED_SOURCE = ipaddress.ip_address("10.77.0.10")
TABLE = "mini_soc_ar"
SET = "blocked_ipv4"


def log(message):
    stamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    with open(LOG, "a", encoding="utf-8") as handle:
        handle.write(f"{stamp} mini-soc-nft-block.py: {message}\n")


def run_nft(args, *, check=True):
    return subprocess.run(
        [NFT, *args],
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def ensure_runtime_table():
    if run_nft(["list", "table", "inet", TABLE], check=False).returncode == 0:
        return
    rules = f"""table inet {TABLE} {{
    set {SET} {{
        type ipv4_addr
    }}
    chain forward {{
        type filter hook forward priority -10; policy accept;
        ip saddr @{SET} drop
    }}
}}
"""
    subprocess.run(
        [NFT, "-f", "-"],
        input=rules,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def read_message():
    line = sys.stdin.readline()
    if not line:
        raise ValueError("empty stdin")
    return json.loads(line)


def source_from(message):
    raw = message["parameters"]["alert"]["data"]["src_ip"]
    source = ipaddress.ip_address(raw)
    if source.version != 4 or source != ALLOWED_SOURCE:
        raise ValueError(f"source outside CHG-021 allowlist: {source}")
    return str(source)


def check_keys(source):
    control = {
        "version": 1,
        "origin": {"name": "mini-soc-nft-block.py", "module": "active-response"},
        "command": "check_keys",
        "parameters": {"keys": [source]},
    }
    print(json.dumps(control), flush=True)
    response = read_message()
    return response.get("command") == "continue"


def add(source):
    ensure_runtime_table()
    result = run_nft(
        ["add", "element", "inet", TABLE, SET, "{", source, "}"],
        check=False,
    )
    if result.returncode != 0 and "File exists" not in result.stderr:
        raise RuntimeError(result.stderr.strip())
    log(f"ADD source={source}")


def delete(source):
    if run_nft(["list", "table", "inet", TABLE], check=False).returncode != 0:
        log(f"DELETE source={source} table_absent=true")
        return
    result = run_nft(
        ["delete", "element", "inet", TABLE, SET, "{", source, "}"],
        check=False,
    )
    if result.returncode != 0 and "No such file or directory" not in result.stderr:
        raise RuntimeError(result.stderr.strip())
    log(f"DELETE source={source}")


def main():
    try:
        message = read_message()
        command = message.get("command")
        source = source_from(message)

        if command == "add":
            if not check_keys(source):
                log(f"ABORT source={source}")
                return 0
            add(source)
            return 0

        if command == "delete":
            delete(source)
            return 0

        raise ValueError(f"unsupported command: {command}")
    except Exception as exc:
        log(f"ERROR {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
