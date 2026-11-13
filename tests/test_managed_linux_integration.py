# SPDX-License-Identifier: Apache-2.0
"""Offline wiring checks only; never storage or kernel qualification evidence."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


def jobs(text):
    body = text.split("jobs:\n", 1)[1]
    matches = list(re.finditer(r"(?m)^  ([a-z][a-z0-9-]*):\n", body))
    return {match[1]: body[match.end():matches[i + 1].start() if i + 1 < len(matches) else len(body)]
            for i, match in enumerate(matches)}


class ManagedIntegrationTests(unittest.TestCase):
    def test_reusable_qualification_stays_on_standard_runner_with_original_limits(self):
        workflow = (ROOT / ".github/workflows/managed-release.yml").read_text()
        job = jobs(workflow)["managed-release"]
        self.assertRegex(job, r"(?m)^    runs-on: ubuntu-24\.04$")
        self.assertRegex(job, r"(?m)^    timeout-minutes: 90$")
        self.assertRegex(job, r"(?m)^        timeout-minutes: 20$")
        self.assertRegex(job, r"(?m)^        timeout-minutes: 60$")
        self.assertIn("persist-credentials: false", job)
        self.assertIn("ref: ${{ inputs.source_ref }}", job)
        self.assertIn("contents: read", job)
        self.assertNotIn("secrets:", workflow)
        self.assertNotIn("services:", workflow)
        self.assertNotIn("continue-on-error:", workflow)
        self.assertIn("--execute --prepare --source-sha", job)
        self.assertIn("--execute --warden --source-sha", job)
        self.assertIn("sudo -- /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C", job)

    def test_ci_qualifies_current_source_and_requires_non_skipped_success(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        ci = jobs(workflow)
        managed = ci["managed-release"]
        self.assertIn("uses: ./.github/workflows/managed-release.yml", managed)
        self.assertIn("source_ref: ${{ github.sha }}", managed)
        self.assertNotRegex(managed, r"(?m)^    if:")
        aggregate = ci["check"]
        needs = re.search(r"(?m)^    needs: \[([^\]]+)\]$", aggregate)
        self.assertIsNotNone(needs)
        self.assertIn("managed-release", [name.strip() for name in needs[1].split(",")])
        self.assertIn("if: ${{ always() }}", aggregate)
        for outcome in ("failure", "cancelled", "skipped"):
            self.assertIn("contains(join(needs.*.result, ','), '" + outcome + "')", aggregate)
        self.assertIn("run: exit 1", aggregate)

    def test_release_qualifies_final_tag_after_contract_before_registry_build(self):
        release = jobs((ROOT / ".github/workflows/release.yml").read_text())
        managed = release["managed-release"]
        self.assertRegex(managed, r"(?m)^    needs: contract$")
        self.assertIn("uses: ./.github/workflows/managed-release.yml", managed)
        # contract already verifies tag == github.sha. Re-resolving the mutable
        # tag in another job could qualify different bytes after a tag move.
        self.assertIn("source_ref: ${{ github.sha }}", managed)
        self.assertNotIn("source_ref: ${{ inputs.release_tag", managed)
        self.assertNotIn("secrets:", managed)
        build = release["build"]
        self.assertRegex(build, r"(?m)^    needs: \[contract, managed-release\]$")
        self.assertNotIn("continue-on-error:", managed + build)
        self.assertLess(build.index("--phase native-child"), build.index("docker push"))
        self.assertIn("--phase published-replay", build)

    def test_offline_checks_and_immutable_runtime_image_are_required(self):
        justfile = (ROOT / "justfile").read_text()
        ci = jobs((ROOT / ".github/workflows/ci.yml").read_text())["fmt"]
        for entry in (justfile, ci):
            self.assertIn("test_managed_linux_*.py", entry)
            self.assertIn("test_release_relay.py", entry)
        audit = (ROOT / "scripts/audit-dependencies.sh").read_text()
        self.assertIn("Dockerfile.managed-tests", audit)
        dockerfile = (ROOT / "Dockerfile.managed-tests").read_text()
        bases = re.findall(r"(?m)^FROM (\S+)", dockerfile)
        self.assertEqual(len(bases), 1)
        self.assertRegex(bases[0], r"^debian:trixie-slim@sha256:[0-9a-f]{64}$")

    def test_failed_attempt_retention_cannot_substitute_for_a_successful_job(self):
        workflow = (ROOT / ".github/workflows/managed-release.yml").read_text()
        self.assertIn("!cancelled()", workflow)
        self.assertIn("steps.managed.outcome == 'failure'", workflow)
        self.assertIn("steps.managed.outcome == 'success'", workflow)
        self.assertIn("if-no-files-found: error", workflow)
        self.assertIn("path: .managed-release-prepared/qualification.json", workflow)
        self.assertNotIn("continue-on-error:", workflow)


if __name__ == "__main__":
    unittest.main()
