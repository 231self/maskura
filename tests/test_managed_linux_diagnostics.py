# SPDX-License-Identifier: Apache-2.0
"""Pure privacy checks, not runtime qualification or kernel controls."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts.managed_release_linux import controller as C
from scripts.managed_release_linux import protocol as P


class DiagnosticsTests(unittest.TestCase):
    def result(self):
        return dict(schema=1, kind="case-result", case="http", nonce="b" * 32, seq=4,
                    passed=False, status="failed", counts={key: 0 for key in P.COUNT_FIELDS},
                    cleanup={key: False for key in P.CLEANUP_FIELDS},
                    control={key: (0 if key == "python_tests_run" else False) for key in P.CONTROL_FIELDS},
                    panic_locations=[dict(code="MANAGED_CASE", line=123, column=4)])

    def test_failed_case_exports_only_validated_bound_facts_and_still_fails(self):
        frame, output = self.result(), io.StringIO()
        with redirect_stdout(output), self.assertRaises(C.Refused):
            C.closed_result(frame, "http", "b" * 32)
        prefix, data = output.getvalue().strip().split(": ", 1)
        self.assertEqual(prefix, "managed-linux-case-result")
        record = json.loads(data)
        self.assertEqual(set(record), {"case", "init_passed", "status", "counts", "local_cleanup", "panic_locations"})
        self.assertEqual(record, dict(case="http", init_passed=False, status="failed", counts=frame["counts"],
                                     local_cleanup=frame["cleanup"], panic_locations=frame["panic_locations"]))
        self.assertNotIn("b" * 32, output.getvalue())

    def test_unbound_or_private_or_malformed_frames_export_nothing(self):
        for update in (dict(nonce="c" * 32), dict(case="repair-valid"), dict(private="PRIVATE_SECRET"),
                       dict(status="PRIVATE_BODY"), dict(counts={"private": "PRIVATE_BODY"}),
                       dict(panic_locations=[dict(code="PRIVATE_PATH", line=123, column=4)])):
            frame, output = self.result(), io.StringIO()
            frame.update(update)
            with redirect_stdout(output), self.assertRaises(C.Refused):
                C.closed_result(frame, "http", "b" * 32)
            self.assertEqual(output.getvalue(), "")

    def test_only_fixed_refusal_categories_are_exported(self):
        for category in C.CLOSED_FAILURES:
            self.assertEqual(C.failure_category(C.Refused(category)), category)
        for error in (C.Refused("PRIVATE_BODY"), ValueError("PRIVATE_CREDENTIAL"),
                      C.Refused("command-failed", "PRIVATE_ARG"), C.Refused({"private": "value"})):
            self.assertEqual(C.failure_category(error), "internal-failure")

    def test_exception_stringification_is_never_used(self):
        class PrivateError(Exception):
            def __str__(self):
                raise AssertionError("exception text must not be inspected")
        self.assertEqual(C.failure_category(PrivateError()), "internal-failure")

    def test_prepare_failure_prints_only_closed_category_and_remains_failure(self):
        for error, category in ((C.Refused("command-deadline"), "command-deadline"),
                                (ValueError("PRIVATE_PROMPT"), "internal-failure")):
            output = io.StringIO()
            with patch.object(C, "prepare", side_effect=error), patch.object(C, "Host"), redirect_stdout(output):
                code = C.main(["--execute", "--prepare", "--source-sha", "a" * 40])
            self.assertEqual(code, 1)
            self.assertIn(category, output.getvalue())
            self.assertNotIn("PRIVATE", output.getvalue())

    def test_warden_failed_receipt_cannot_assert_acceptance_or_cleanup(self):
        output, writes = io.StringIO(), []
        with patch.object(C, "Host"), \
             patch.object(C, "validate_prepared", side_effect=C.Refused("mount-flags-unproved")), \
             patch.object(C, "Warden") as warden, \
             patch.object(Path, "write_bytes", side_effect=lambda data: writes.append(data)), \
             patch.object(Path, "chmod"), redirect_stdout(output):
            code = C.main(["--execute", "--warden", "--source-sha", "a" * 40])
        self.assertEqual(code, 1)
        warden.assert_not_called()
        self.assertEqual(len(writes), 1)
        receipt = json.loads(writes[0])
        self.assertIs(receipt["passed"], False)
        self.assertIs(receipt["cleanup"], False)
        self.assertEqual(receipt["cases"], 0)
        self.assertEqual(receipt["failure_category"], "mount-flags-unproved")

    def test_native_guard_compile_precedes_heavy_build_in_same_budget(self):
        source = (Path(__file__).resolve().parents[1] / "scripts/managed_release_linux/controller.py").read_text()
        prepare = source.split("def prepare(", 1)[1].split("def validate_prepared(", 1)[0]
        self.assertLess(prepare.index('"/usr/bin/gcc"'), prepare.index('"rustup"'))
        self.assertLess(prepare.index('"--self-test"'), prepare.index('"rustup"'))
        self.assertEqual(prepare.count("host.clock() + PREP_SECONDS"), 1)


if __name__ == "__main__":
    unittest.main()
