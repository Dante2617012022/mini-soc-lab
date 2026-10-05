#!/usr/bin/python3
"""Manual protocol harness for CHG-021 Active Response UAT.

Runs the deployed script, answers its check_keys request with continue,
and submits either add or delete for the authorized lab source.
"""

import argparse
import json
import subprocess
import sys

SCRIPT = "/var/ossec/active-response/bin/mini-soc-nft-block.py"
SOURCE = "10.77.0.10"


def message(command):
    return {
        "version": 1,
        "origin": {"name": "chg-021-harness", "module": "active-response"},
        "command": command,
        "parameters": {"alert": {"data": {"src_ip": SOURCE}}},
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("add", "delete"))
    args = parser.parse_args()

    proc = subprocess.Popen(
        [SCRIPT],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None

    proc.stdin.write(json.dumps(message(args.command)) + "\n")
    proc.stdin.flush()

    if args.command == "add":
        check = json.loads(proc.stdout.readline())
        if check.get("command") != "check_keys" or check.get("parameters", {}).get("keys") != [SOURCE]:
            proc.kill()
            print(f"unexpected check_keys payload: {check}", file=sys.stderr)
            return 2
        proc.stdin.write(json.dumps({"command": "continue"}) + "\n")
        proc.stdin.flush()

    proc.stdin.close()
    stderr = proc.stderr.read() if proc.stderr else ""
    rc = proc.wait()
    if stderr:
        print(stderr, file=sys.stderr, end="")
    return rc


if __name__ == "__main__":
    sys.exit(main())
