"""Offline contract tests: no real firewall, Wazuh process or privileged writes."""

import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, call, patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts" / "active-response"
SOURCE = "10.77.0.10"
NFT = "/usr/sbin/nft"
LIST_TABLE = [NFT, "list", "table", "inet", "mini_soc_ar"]
ADD_ELEMENT = [
    NFT, "add", "element", "inet", "mini_soc_ar", "blocked_ipv4", "{", SOURCE, "}"
]
DELETE_ELEMENT = [
    NFT, "delete", "element", "inet", "mini_soc_ar", "blocked_ipv4", "{", SOURCE, "}"
]


def load_script(filename):
    spec = importlib.util.spec_from_file_location(filename.replace("-", "_"), SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def event(command="add", source=SOURCE):
    return {
        "version": 1,
        "origin": {"name": "test", "module": "active-response"},
        "command": command,
        "parameters": {"alert": {"data": {"src_ip": source}}},
    }


def lines(*messages):
    return "".join(json.dumps(message) + "\n" for message in messages)


def result(returncode=0, stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout="", stderr=stderr)


class ActiveResponseTests(unittest.TestCase):
    def setUp(self):
        self.response = load_script("mini-soc-nft-block.py")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.log_path = Path(temporary.name) / "active-response.log"
        self.response.LOG = str(self.log_path)
        nft_patch = patch.object(
            self.response.subprocess,
            "run",
            autospec=True,
            side_effect=AssertionError("unexpected nftables invocation"),
        )
        self.nft = nft_patch.start()
        self.addCleanup(nft_patch.stop)

    def invoke(self, data):
        self.log_path.write_text("", encoding="utf-8")
        output = io.StringIO()
        with patch.object(self.response.sys, "stdin", io.StringIO(data)), patch.object(
            self.response.sys, "stdout", output
        ):
            code = self.response.main()
        messages = [json.loads(line) for line in output.getvalue().splitlines()]
        return code, messages, self.log_path.read_text(encoding="utf-8")

    def nft_results(self, *results):
        self.nft.side_effect = results

    def assert_commands(self, *commands):
        self.assertEqual([item.args[0] for item in self.nft.call_args_list], list(commands))
        for invocation in self.nft.call_args_list:
            self.assertNotIn("shell", invocation.kwargs)
            self.assertTrue(invocation.kwargs["text"])
            self.assertEqual(invocation.kwargs["stdout"], subprocess.PIPE)
            self.assertEqual(invocation.kwargs["stderr"], subprocess.PIPE)

    def assert_check_keys(self, messages):
        self.assertEqual(messages, [{
            "version": 1,
            "origin": {"name": "mini-soc-nft-block.py", "module": "active-response"},
            "command": "check_keys",
            "parameters": {"keys": [SOURCE]},
        }])

    def test_invalid_json_or_eof_never_reaches_nftables(self):
        for raw in ("", "\n", "{broken\n", '{"command": "add"\n'):
            with self.subTest(raw=raw):
                code, output, log = self.invoke(raw)
                self.assertEqual(code, 1)
                self.assertEqual(output, [])
                self.assertIn("ERROR", log)
                self.nft.assert_not_called()

    def test_incomplete_or_wrong_message_shapes_never_reach_nftables(self):
        malformed = (
            None, [], 7, "add", {}, {"command": "add"},
            {"command": "add", "parameters": None},
            {"command": "add", "parameters": []},
            {"command": "add", "parameters": {}},
            {"command": "add", "parameters": {"alert": None}},
            {"command": "add", "parameters": {"alert": {}}},
            {"command": "add", "parameters": {"alert": {"data": []}}},
            {"command": "add", "parameters": {"alert": {"data": {}}}},
        )
        for message in malformed:
            with self.subTest(message=message):
                code, output, log = self.invoke(lines(message))
                self.assertEqual(code, 1)
                self.assertEqual(output, [])
                self.assertIn("ERROR", log)
                self.nft.assert_not_called()

    def test_out_of_scope_or_invalid_sources_rejected_for_add_and_delete(self):
        sources = (
            "10.77.0.1", "10.77.0.11", "192.0.2.1", "127.0.0.1",
            "0.0.0.0", "::1", "::ffff:10.77.0.10", "not-an-ip",
            "10.77.0.10/32", "10.77.0.10; unexpected-command", None, [], {},
        )
        for command in ("add", "delete"):
            for source in sources:
                with self.subTest(command=command, source=source):
                    code, output, log = self.invoke(lines(event(command, source)))
                    self.assertEqual(code, 1)
                    self.assertEqual(output, [])
                    self.assertIn("ERROR", log)
                    self.nft.assert_not_called()

    def test_unsupported_commands_never_reach_nftables(self):
        for command in ("flush", "ADD", "continue", "", None, []):
            with self.subTest(command=command):
                code, output, log = self.invoke(lines(event(command)))
                self.assertEqual(code, 1)
                self.assertEqual(output, [])
                self.assertIn("unsupported command", log)
                self.nft.assert_not_called()

    def test_only_continue_authorizes_add(self):
        for response in ({"command": "abort"}, {"command": "add"}, {}, {"command": None}):
            with self.subTest(response=response):
                code, output, log = self.invoke(lines(event(), response))
                self.assertEqual(code, 0)
                self.assert_check_keys(output)
                self.assertIn(f"ABORT source={SOURCE}", log)
                self.assertNotIn("ADD source=", log)
                self.nft.assert_not_called()

    def test_malformed_control_response_or_eof_fails_without_blocking(self):
        for control in ("", "broken\n", "null\n", "[]\n", '"continue"\n'):
            with self.subTest(control=control):
                code, output, log = self.invoke(lines(event()) + control)
                self.assertEqual(code, 1)
                self.assert_check_keys(output)
                self.assertIn("ERROR", log)
                self.assertNotIn("ADD source=", log)
                self.nft.assert_not_called()

    def test_add_uses_existing_table_after_continue(self):
        self.nft_results(result(), result())
        code, output, log = self.invoke(lines(event(), {"command": "continue"}))
        self.assertEqual(code, 0)
        self.assert_check_keys(output)
        self.assert_commands(LIST_TABLE, ADD_ELEMENT)
        self.assertIn(f"ADD source={SOURCE}", log)
        self.assertNotIn("ERROR", log)

    def test_first_add_creates_only_dedicated_runtime_forwarding_table(self):
        self.nft_results(result(1, "No such file or directory"), result(), result())
        code, output, log = self.invoke(lines(event(), {"command": "continue"}))
        self.assertEqual(code, 0)
        self.assert_check_keys(output)
        self.assert_commands(LIST_TABLE, [NFT, "-f", "-"], ADD_ELEMENT)
        creation = self.nft.call_args_list[1]
        self.assertTrue(creation.kwargs["check"])
        self.assertEqual(creation.kwargs["input"], """table inet mini_soc_ar {
    set blocked_ipv4 {
        type ipv4_addr
    }
    chain forward {
        type filter hook forward priority -10; policy accept;
        ip saddr @blocked_ipv4 drop
    }
}
""")
        self.assertIn(f"ADD source={SOURCE}", log)

    def test_duplicate_add_is_idempotent(self):
        self.nft_results(result(), result(1, "Error: File exists"))
        code, _, log = self.invoke(lines(event(), {"command": "continue"}))
        self.assertEqual(code, 0)
        self.assert_commands(LIST_TABLE, ADD_ELEMENT)
        self.assertIn(f"ADD source={SOURCE}", log)
        self.assertNotIn("ERROR", log)

    def test_failed_table_creation_stops_before_adding_element(self):
        failure = subprocess.CalledProcessError(1, [NFT, "-f", "-"], stderr="Operation not permitted")
        self.nft_results(result(1, "No such file or directory"), failure)
        code, _, log = self.invoke(lines(event(), {"command": "continue"}))
        self.assertEqual(code, 1)
        self.assert_commands(LIST_TABLE, [NFT, "-f", "-"])
        self.assertIn("ERROR CalledProcessError", log)
        self.assertNotIn("ADD source=", log)

    def test_failed_add_reports_error_without_success_log(self):
        self.nft_results(result(), result(1, "Operation not permitted"))
        code, _, log = self.invoke(lines(event(), {"command": "continue"}))
        self.assertEqual(code, 1)
        self.assert_commands(LIST_TABLE, ADD_ELEMENT)
        self.assertIn("ERROR RuntimeError: Operation not permitted", log)
        self.assertNotIn("ADD source=", log)

    def test_missing_nft_executable_reports_error(self):
        for command in ("add", "delete"):
            with self.subTest(command=command):
                self.nft.reset_mock()
                self.nft_results(FileNotFoundError("nft unavailable"))
                data = lines(event(command))
                if command == "add":
                    data += lines({"command": "continue"})
                code, _, log = self.invoke(data)
                self.assertEqual(code, 1)
                self.assert_commands(LIST_TABLE)
                self.assertIn("ERROR FileNotFoundError", log)
                self.assertNotIn(f"{command.upper()} source=", log)

    def test_delete_removes_only_authorized_element_without_check_keys(self):
        self.nft_results(result(), result())
        code, output, log = self.invoke(lines(event("delete")))
        self.assertEqual(code, 0)
        self.assertEqual(output, [])
        self.assert_commands(LIST_TABLE, DELETE_ELEMENT)
        self.assertIn(f"DELETE source={SOURCE}", log)
        self.assertNotIn("ERROR", log)

    def test_delete_of_missing_table_is_idempotent(self):
        self.nft_results(result(1, "No such file or directory"))
        code, output, log = self.invoke(lines(event("delete")))
        self.assertEqual(code, 0)
        self.assertEqual(output, [])
        self.assert_commands(LIST_TABLE)
        self.assertIn(f"DELETE source={SOURCE} table_absent=true", log)

    def test_delete_of_missing_element_is_idempotent(self):
        self.nft_results(result(), result(1, "No such file or directory"))
        code, _, log = self.invoke(lines(event("delete")))
        self.assertEqual(code, 0)
        self.assert_commands(LIST_TABLE, DELETE_ELEMENT)
        self.assertNotIn("ERROR", log)

    def test_failed_delete_reports_error_without_success_log(self):
        self.nft_results(result(), result(1, "Operation not permitted"))
        code, output, log = self.invoke(lines(event("delete")))
        self.assertEqual(code, 1)
        self.assertEqual(output, [])
        self.assert_commands(LIST_TABLE, DELETE_ELEMENT)
        self.assertIn("ERROR RuntimeError: Operation not permitted", log)
        self.assertNotIn("DELETE source=", log)


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.harness = load_script("chg-021-harness.py")
        self.process = Mock(spec=["stdin", "stdout", "stderr", "wait", "kill"])
        self.process.stdin = Mock(spec=io.TextIOBase)
        self.process.stdout = io.StringIO(lines({
            "command": "check_keys", "parameters": {"keys": [SOURCE]}
        }))
        self.process.stderr = io.StringIO("")
        self.process.wait.return_value = 0
        process_patch = patch.object(self.harness.subprocess, "Popen", autospec=True)
        self.popen = process_patch.start()
        self.popen.return_value = self.process
        self.addCleanup(process_patch.stop)

    def invoke(self, command):
        error = io.StringIO()
        with patch.object(self.harness.sys, "argv", ["chg-021-harness.py", command]), patch.object(
            self.harness.sys, "stderr", error
        ):
            code = self.harness.main()
        return code, error.getvalue()

    def sent_messages(self):
        return [json.loads(item.args[0]) for item in self.process.stdin.write.call_args_list]

    def assert_event(self, payload, command):
        self.assertEqual(payload, {
            "version": 1,
            "origin": {"name": "chg-021-harness", "module": "active-response"},
            "command": command,
            "parameters": {"alert": {"data": {"src_ip": SOURCE}}},
        })

    def test_add_sends_authorized_event_then_continue(self):
        code, error = self.invoke("add")
        self.assertEqual(code, 0)
        self.assertEqual(error, "")
        self.popen.assert_called_once_with(
            ["/var/ossec/active-response/bin/mini-soc-nft-block.py"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        messages = self.sent_messages()
        self.assertEqual(len(messages), 2)
        self.assert_event(messages[0], "add")
        self.assertEqual(messages[1], {"command": "continue"})
        self.assertEqual(self.process.stdin.method_calls, [
            call.write(lines(messages[0])), call.flush(),
            call.write(lines(messages[1])), call.flush(), call.close(),
        ])
        self.process.wait.assert_called_once_with()
        self.process.kill.assert_not_called()

    def test_delete_does_not_wait_for_a_check_keys_payload(self):
        self.process.stdout = Mock(spec=io.TextIOBase)
        code, error = self.invoke("delete")
        self.assertEqual(code, 0)
        self.assertEqual(error, "")
        messages = self.sent_messages()
        self.assertEqual(len(messages), 1)
        self.assert_event(messages[0], "delete")
        self.process.stdout.readline.assert_not_called()
        self.process.stdin.close.assert_called_once_with()
        self.process.wait.assert_called_once_with()

    def test_wrong_control_command_or_keys_never_sends_continue(self):
        bad_checks = (
            {"command": "abort", "parameters": {"keys": [SOURCE]}},
            {"command": "check_keys", "parameters": {"keys": ["10.77.0.11"]}},
            {"command": "check_keys", "parameters": {"keys": [SOURCE, "10.77.0.11"]}},
            {"command": "check_keys", "parameters": {"keys": []}},
            {"command": "check_keys"},
        )
        for message in bad_checks:
            with self.subTest(message=message):
                self.process.reset_mock()
                self.process.stdout = io.StringIO(lines(message))
                code, error = self.invoke("add")
                self.assertEqual(code, 2)
                self.assertIn("unexpected check_keys payload", error)
                self.assertEqual(len(self.sent_messages()), 1)
                self.assert_event(self.sent_messages()[0], "add")
                self.process.kill.assert_called_once_with()

    def test_child_failure_is_propagated_with_stderr(self):
        for command in ("add", "delete"):
            with self.subTest(command=command):
                self.process.stderr = io.StringIO("simulated child error\n")
                self.process.wait.return_value = 1
                code, error = self.invoke(command)
                self.assertEqual(code, 1)
                self.assertEqual(error, "simulated child error\n")

    def test_unsupported_cli_command_does_not_start_child(self):
        with self.assertRaises(SystemExit) as raised:
            self.invoke("flush")
        self.assertEqual(raised.exception.code, 2)
        self.popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
