"""Exercise the response against real nftables in a disposable network namespace.

Run with: sudo unshare --net -- python3 tests/integration/active_response_nft.py
Never deploys to Wazuh or uses the host network namespace.
"""

import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/active-response/mini-soc-nft-block.py"
NFT = "/usr/sbin/nft"
SOURCE = "10.77.0.10"


def nft_json(*args):
    output = subprocess.run([NFT, "-j", *args], check=True, capture_output=True, text=True)
    return json.loads(output.stdout)["nftables"]


def blocked_sources():
    entries = nft_json("list", "set", "inet", "mini_soc_ar", "blocked_ipv4")
    return next(entry["set"].get("elem", []) for entry in entries if "set" in entry)


def payload(command):
    message = {"command": command, "parameters": {"alert": {"data": {"src_ip": SOURCE}}}}
    return json.dumps(message) + "\n" + (
        json.dumps({"command": "continue"}) + "\n" if command == "add" else ""
    )


def invoke(response, command):
    previous_stdin, previous_stdout = sys.stdin, sys.stdout
    try:
        sys.stdin, sys.stdout = io.StringIO(payload(command)), io.StringIO()
        code = response.main()
        output = sys.stdout.getvalue()
    finally:
        sys.stdin, sys.stdout = previous_stdin, previous_stdout
    assert code == 0, f"{command} returned {code}; inspect the temporary response log"
    if command == "add":
        check = json.loads(output)
        assert check["command"] == "check_keys"
        assert check["parameters"]["keys"] == [SOURCE]
    else:
        assert output == ""


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run as root inside a fresh network namespace (see module docstring).")
    try:
        current_network = os.readlink("/proc/self/ns/net")
        host_network = os.readlink("/proc/1/ns/net")
    except OSError as exc:
        raise SystemExit(f"Cannot verify network namespace isolation: {exc}") from exc
    if current_network == host_network:
        raise SystemExit("Refusing to modify the host network namespace; use unshare --net.")
    if any("table" in entry for entry in nft_json("list", "tables")):
        raise SystemExit("Expected an empty disposable namespace; refusing to alter existing tables.")

    subprocess.run([NFT, "--version"], check=True)
    spec = importlib.util.spec_from_file_location("response", SCRIPT)
    response = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(response)
    with tempfile.TemporaryDirectory() as directory:
        response.LOG = str(Path(directory) / "response.log")
        invoke(response, "delete")
        assert "table_absent=true" in Path(response.LOG).read_text()
        print("PASS: confirmed absence is idempotent")

        invoke(response, "add")
        assert blocked_sources() == [SOURCE]
        invoke(response, "add")
        assert blocked_sources() == [SOURCE]
        print("PASS: add and repeated add contain only the authorized source")

        # Removing CAP_NET_ADMIN from the bounding set also prevents nft from
        # regaining it through exec. The child still has access to its temp log.
        child = """import importlib.util, sys
spec = importlib.util.spec_from_file_location('response', sys.argv[1])
response = importlib.util.module_from_spec(spec)
spec.loader.exec_module(response)
response.LOG = sys.argv[2]
sys.exit(response.main())
"""
        for command in ("add", "delete"):
            denied_log = Path(directory) / f"denied-{command}.log"
            denied = subprocess.run(
                ["setpriv", "--bounding-set=-net_admin", sys.executable, "-c", child,
                 str(SCRIPT), str(denied_log)],
                input=payload(command), capture_output=True, text=True, timeout=15,
            )
            assert denied.returncode == 1, (command, denied.returncode, denied.stderr)
            log = denied_log.read_text()
            assert "ERROR RuntimeError: nft table query failed" in log, log
            assert "table_absent=true" not in log, log
            assert f"{command.upper()} source=" not in log, log
            assert blocked_sources() == [SOURCE]
            print(f"PASS: real permission denial during {command} reports failure and preserves state")

        invoke(response, "delete")
        assert blocked_sources() == []
        invoke(response, "delete")
        assert blocked_sources() == []
        print("PASS: delete and repeated delete leave an empty set")
    print("Integration passed; the disposable namespace is discarded on exit.")


if __name__ == "__main__":
    main()
