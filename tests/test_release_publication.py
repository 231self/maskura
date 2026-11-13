# SPDX-License-Identifier: Apache-2.0
"""Offline publication decisions and focused workflow wiring regressions."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shlex
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_publication", ROOT / "scripts/check-release-publication.py")
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
REPOSITORY = "example/maskura"
TAG = "v9.9.9"
SOURCE = "a" * 40
BASE = "/repos/" + REPOSITORY
REF = BASE + "/git/ref/tags/" + TAG
RELEASE = BASE + "/releases/tags/" + TAG
FIRST_PAGE = BASE + "/releases?per_page=100&page=1"
MISSING = {"message": "Not Found"}


def target(kind="commit", sha=SOURCE):
    return {"type": kind, "sha": sha}


def ref(obj=None):
    return {"ref": "refs/tags/" + TAG, "object": target() if obj is None else obj}


class API:
    def __init__(self):
        self.routes = {REF: (200, ref()), RELEASE: (404, MISSING), FIRST_PAGE: (200, [])}
        self.calls = []

    def __call__(self, endpoint):
        self.calls.append(endpoint)
        status, value = self.routes[endpoint]
        return status, value if isinstance(value, bytes) else json.dumps(value).encode()


def jobs(text):
    """Read only indentation-delimited job/step blocks used by these workflows."""
    matches = list(re.finditer(r"(?m)^  ([a-z][a-z0-9-]*):\n", text.split("jobs:\n", 1)[1]))
    body = text.split("jobs:\n", 1)[1]
    return {match[1]: body[match.end():matches[i + 1].start() if i + 1 < len(matches) else len(body)]
            for i, match in enumerate(matches)}


def steps(job):
    return re.split(r"(?m)^      - ", job)[1:]


def scalar(block, key, indent):
    found = re.search(r"(?m)^" + " " * indent + re.escape(key) + r": (.+)$", block)
    return found[1] if found else None


class OfflineTests(unittest.TestCase):
    def setUp(self):
        # Every test, including workflow controls, denies actual processes/network.
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for name in ("subprocess.run", "subprocess.Popen", "socket.socket",
                     "socket.create_connection", "urllib.request.urlopen"):
            self.stack.enter_context(patch(name, side_effect=AssertionError("external I/O forbidden")))


class PublicationTests(OfflineTests):
    def check(self, api):
        guard.check_publication(REPOSITORY, TAG, SOURCE, api)

    def test_lightweight_tag_and_explicit_release_absence(self):
        api = API()
        self.check(api)
        self.assertEqual(api.calls, [REF, RELEASE, FIRST_PAGE])

    def test_existing_published_or_draft_release_refused(self):
        for draft in (False, True):
            api = API()
            api.routes[RELEASE] = (200, {"tag_name": TAG, "draft": draft})
            with self.subTest(draft=draft), self.assertRaisesRegex(
                    guard.PublicationError, "release-already-exists"):
                self.check(api)
            self.assertNotIn(FIRST_PAGE, api.calls)

    def test_draft_hidden_by_tag_lookup_is_found_in_list(self):
        api = API()
        api.routes[FIRST_PAGE] = (200, [{"tag_name": TAG, "draft": True}])
        with self.assertRaisesRegex(guard.PublicationError, "release-already-exists"):
            self.check(api)

    def test_missing_tag_or_wrong_commit_never_checks_release_absence(self):
        for value, category in (((404, MISSING), "release-tag-missing"),
                                ((200, ref(target(sha="b" * 40))), "tag-source-mismatch")):
            api = API()
            api.routes[REF] = value
            with self.subTest(category=category), self.assertRaisesRegex(guard.PublicationError, category):
                self.check(api)
            self.assertEqual(api.calls, [REF])

    def test_authentication_and_transient_statuses_never_mean_absence(self):
        for endpoint in (REF, RELEASE, FIRST_PAGE):
            for status in (0, 201, 301, 401, 403, 429, 500, 503):
                api = API()
                api.routes[endpoint] = (status, {"message": "PRIVATE_API_SENTINEL"})
                with self.subTest(endpoint=endpoint, status=status), self.assertRaisesRegex(
                        guard.PublicationError, "api-request-failed"):
                    self.check(api)

    def test_only_release_lookup_may_be_missing(self):
        api = API()
        api.routes[FIRST_PAGE] = (404, MISSING)
        with self.assertRaisesRegex(guard.PublicationError, "release-list-invalid"):
            self.check(api)

    def test_malformed_responses_fail_closed(self):
        changes = (
            (REF, (200, [])), (REF, (200, {"ref": "other", "object": target()})),
            (REF, (200, ref({"type": "tree", "sha": SOURCE}))),
            (REF, (200, ref(target(sha="invalid")))),
            (RELEASE, (404, b"not-json")), (RELEASE, (404, {})),
            (RELEASE, (404, b'{"message":"Not Found","message":"Not Found"}')),
            (FIRST_PAGE, (200, {})), (FIRST_PAGE, (200, [{"tag_name": TAG}])),
            (FIRST_PAGE, (200, [{"tag_name": "old", "draft": "false"}])),
            (FIRST_PAGE, (200, b"\xff")),
            (FIRST_PAGE, (200, b"[" * 2000 + b"]" * 2000)),
            (FIRST_PAGE, (200, b" " * (guard.MAX_RESPONSE_BYTES + 1))),
        )
        for endpoint, value in changes:
            api = API()
            api.routes[endpoint] = value
            with self.subTest(endpoint=endpoint, value_type=type(value[1])), self.assertRaises(
                    guard.PublicationError):
                self.check(api)

    def test_annotated_tags_peel_to_source_with_identity_checks(self):
        api = API()
        first, second = "b" * 40, "c" * 40
        api.routes[REF] = (200, ref(target("tag", first)))
        api.routes[BASE + "/git/tags/" + first] = (200, {"sha": first, "object": target("tag", second)})
        api.routes[BASE + "/git/tags/" + second] = (200, {"sha": second, "object": target()})
        self.check(api)
        self.assertEqual(len(api.calls), 5)
        for status, obj in ((404, MISSING), (200, {"sha": first, "object": target()}),
                            (200, {"sha": second, "object": target(sha="d" * 40)})):
            api.routes[BASE + "/git/tags/" + second] = status, obj
            with self.subTest(status=status, obj=obj), self.assertRaises(guard.PublicationError):
                self.check(api)

    def test_annotated_cycle_and_depth_are_bounded(self):
        api = API()
        annotated = "b" * 40
        api.routes[REF] = (200, ref(target("tag", annotated)))
        api.routes[BASE + "/git/tags/" + annotated] = (
            200, {"sha": annotated, "object": target("tag", annotated)})
        with self.assertRaisesRegex(guard.PublicationError, "tag-peel-limit"):
            self.check(api)
        self.assertEqual(len(api.calls), 2)
        api = API()
        chain = [f"{i + 1:040x}" for i in range(guard.MAX_TAG_OBJECTS + 1)]
        api.routes[REF] = (200, ref(target("tag", chain[0])))
        for current, following in zip(chain, chain[1:]):
            api.routes[BASE + "/git/tags/" + current] = (
                200, {"sha": current, "object": target("tag", following)})
        with self.assertRaisesRegex(guard.PublicationError, "tag-peel-limit"):
            self.check(api)
        self.assertEqual(len(api.calls), 1 + guard.MAX_TAG_OBJECTS)
        last = chain[guard.MAX_TAG_OBJECTS - 1]
        api.routes[BASE + "/git/tags/" + last] = (200, {"sha": last, "object": target()})
        self.check(api)  # The last permitted tag can resolve to the commit.

    def test_release_pagination_includes_late_drafts_and_has_a_hard_bound(self):
        api = API()
        page = [{"tag_name": "old", "draft": False}] * guard.PAGE_SIZE
        for number in range(1, guard.MAX_RELEASE_PAGES + 1):
            api.routes[f"{BASE}/releases?per_page=100&page={number}"] = (200, page)
        with self.assertRaisesRegex(guard.PublicationError, "release-list-limit"):
            self.check(api)
        self.assertEqual(len(api.calls), 2 + guard.MAX_RELEASE_PAGES)
        last = f"{BASE}/releases?per_page=100&page={guard.MAX_RELEASE_PAGES}"
        api.routes[last] = (200, [{"tag_name": TAG, "draft": True}])
        with self.assertRaisesRegex(guard.PublicationError, "release-already-exists"):
            self.check(api)
        api.routes[last] = (200, [])
        self.check(api)

    def test_invalid_identity_and_missing_authentication_do_not_fetch(self):
        api = API()
        for repository, tag, source in (("bad/repo/extra", TAG, SOURCE),
                                        (REPOSITORY, "latest", SOURCE),
                                        (REPOSITORY, TAG, "not-a-sha")):
            with self.assertRaises(guard.PublicationError):
                guard.check_publication(repository, tag, source, api)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(guard.main({}, api), 1)
        self.assertIn("authentication-required", output.getvalue())
        self.assertEqual(api.calls, [])

    def test_cli_messages_do_not_disclose_token_or_api_response(self):
        api = API()
        env = dict(GH_TOKEN="PRIVATE_TOKEN_SENTINEL", GITHUB_REPOSITORY=REPOSITORY,
                   GITHUB_SHA=SOURCE, RELEASE_TAG=TAG)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(guard.main(env, api), 0)
        self.assertEqual(output.getvalue(), "release publication guard passed\n")
        api.routes[RELEASE] = (403, {"message": "PRIVATE_API_SENTINEL"})
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(guard.main(env, api), 1)
        self.assertEqual(output.getvalue(), "release publication refused: api-request-failed\n")

    def test_real_cli_adapter_requires_status_and_matching_exit_code(self):
        for newline in (b"\n", b"\r\n"):
            for status, code in ((200, 0), (404, 1)):
                wire = newline.join([f"HTTP/2.0 {status} Status".encode(), b"Content-Type: application/json", b"", b"{}"])
                result = SimpleNamespace(returncode=code, stdout=wire)
                with patch("subprocess.run", return_value=result) as run:
                    self.assertEqual(guard.gh_get(REF), (status, b"{}"))
                args, kwargs = run.call_args
                self.assertEqual(args[0][-1], REF)
                self.assertIn("--include", args[0])
                self.assertNotIn("PRIVATE_TOKEN_SENTINEL", str(args))
                self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
                self.assertEqual(kwargs["timeout"], 30)
        for status, code in ((200, 1), (404, 0), (401, 1), (403, 1), (503, 1)):
            result = SimpleNamespace(returncode=code, stdout=f"HTTP/2.0 {status} Status\n\n{{}}".encode())
            with patch("subprocess.run", return_value=result), self.assertRaises(guard.PublicationError):
                guard.gh_get(REF)
        for body in (b"{}", b"HTTP/2.0 nope\n\n{}", b" " * (guard.MAX_RESPONSE_BYTES + 1)):
            with patch("subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=body)), self.assertRaises(guard.PublicationError):
                guard.gh_get(REF)
        for error in (OSError("PRIVATE_ERROR"), subprocess.TimeoutExpired("private", 30)):
            with patch("subprocess.run", side_effect=error), self.assertRaisesRegex(
                    guard.PublicationError, "^api-transport-failed$"):
                guard.gh_get(REF)


class WorkflowTests(OfflineTests):
    def setUp(self):
        super().setUp()
        self.ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.release = (ROOT / ".github/workflows/release.yml").read_text()

    def assert_early_gate(self, text):
        all_jobs = jobs(text)
        contract = all_jobs["contract"]
        guard_steps = [s for s in steps(contract) if "scripts/check-release-publication.py" in s]
        self.assertEqual(len(guard_steps), 1)
        self.assertEqual(scalar(guard_steps[0], "run", 8), "python3 -B scripts/check-release-publication.py")
        self.assertEqual(scalar(guard_steps[0], "GH_TOKEN", 10), "${{ secrets.GITHUB_TOKEN }}")
        self.assertNotIn("continue-on-error:", contract)
        self.assertNotRegex(contract, r"(?m)^\s+if:")
        self.assertNotRegex(guard_steps[0], r"(?m)^(?:        )?(?:if|continue-on-error):")
        self.assertLess(contract.index("scripts/check-release-contract.py"), contract.index("scripts/check-release-publication.py"))
        self.assertNotRegex(contract, r"docker (?:push|buildx)|gh release create")

        def requires_contract(name, visited=None):
            if name == "contract":
                return True
            visited = set() if visited is None else visited
            self.assertNotIn(name, visited)
            visited = visited | {name}
            needs = scalar(all_jobs[name], "needs", 4)
            self.assertIsNotNone(needs, name)
            dependencies = [n.strip() for n in needs.strip("[]").split(",")]
            return any(requires_contract(n, visited) for n in dependencies)

        for name, job in all_jobs.items():
            self.assertTrue(requires_contract(name), name)
            self.assertNotRegex(job.split("    steps:", 1)[0], r"(?m)^    if:")
        self.assertNotIn("gh release view", all_jobs["release"])
        self.assertIn("gh release create", all_jobs["release"])

    def assert_serialized(self, text):
        header = text.split("\nenv:", 1)[0].split("\nconcurrency:\n", 1)[1]
        self.assertEqual(scalar(header, "cancel-in-progress", 2), "false")
        self.assertEqual(scalar(header, "group", 2),
                         "release-${{ github.repository }}-${{ inputs.release_tag && format('refs/tags/{0}', inputs.release_tag) || github.ref }}")

    def assert_dependencies_and_receipts(self, ci, release):
        for text, job_name in ((ci, "release-image-smoke"), (release, "build")):
            job = jobs(text)[job_name]
            header = job.split("    steps:", 1)[0]
            rows = re.findall(r"(?m)^          - platform: (\S+)\n            suffix: (\S+)\n            runs-on: (\S+)$", header)
            self.assertEqual(rows, [("linux/amd64", "amd64", "ubuntu-24.04"),
                                    ("linux/arm64", "arm64", "ubuntu-24.04-arm")])
            self.assertEqual(scalar(header, "runs-on", 4), "${{ matrix.runs-on }}")
            ordered = steps(job)
            smokes = [i for i, s in enumerate(ordered) if "bash scripts/release-image-smoke.sh" in s]
            installers = [i for i, s in enumerate(ordered) if re.search(r"python3 -m pip install .*\bawscli\b", s)]
            self.assertEqual(len(smokes), 1)
            self.assertEqual(len(installers), 1)
            self.assertLess(installers[0], smokes[0])
            installer = ordered[installers[0]]
            self.assertIn("python3 -m venv .release-venv", installer)
            self.assertIn('echo "$PWD/.release-venv/bin" >> "$GITHUB_PATH"', installer)
            self.assertNotRegex(installer, r"(?m)^        (?:if|continue-on-error):")
        candidate = steps(jobs(ci)["release-image-smoke"])
        producers = [i for i, s in enumerate(candidate) if "--phase candidate" in s]
        self.assertEqual(len(producers), 1)
        producer = candidate[producers[0]]
        self.assertEqual(scalar(producer, "id", 8), "feedback-regressions")
        run = producer.split("        run: |\n", 1)[1]
        arguments = shlex.split(run.replace("\\\n", " "))
        report = arguments[arguments.index("--report") + 1]
        self.assertEqual(scalar(producer, "ARCH", 10), "${{ matrix.suffix }}")
        uploads = [i for i, s in enumerate(candidate) if scalar(s, "path", 10) == report]
        self.assertEqual(len(uploads), 1)
        self.assertGreater(uploads[0], producers[0])
        upload = candidate[uploads[0]]
        self.assertRegex(scalar(upload, "uses", 8), r"^actions/upload-artifact@[0-9a-f]{40}(?: #.*)?$")
        self.assertEqual(scalar(upload, "name", 10),
                         "maskura-candidate-feedback-${{ matrix.suffix }}-${{ github.run_attempt }}")
        self.assertEqual(scalar(upload, "if-no-files-found", 10), "error")
        self.assertNotRegex(producer, r"(?m)^(?:        )?(?:if|continue-on-error):")
        self.assertEqual(scalar(upload, "if", 8),
                         "${{ !cancelled() && (steps.feedback-regressions.outcome == 'success' || steps.feedback-regressions.outcome == 'failure') }}")
        self.assertNotRegex(upload, r"(?m)^(?:        )?continue-on-error:")
        self.assertNotRegex(upload, r"(?m)^if:")
        proofs = [i for i, s in enumerate(candidate) if "bash examples/prove-maskura.sh" in s]
        self.assertEqual(len(proofs), 1)
        self.assertGreater(proofs[0], uploads[0])
        self.assertNotRegex(candidate[proofs[0]], r"(?m)^(?:        )?(?:if|continue-on-error):")

    def test_all_release_jobs_depend_on_early_fail_closed_contract(self):
        self.assert_early_gate(self.release)

    def test_release_concurrency_matches_both_trigger_paths(self):
        self.assert_serialized(self.release)

    def test_both_native_architectures_install_before_smoke_and_retain_receipts(self):
        self.assert_dependencies_and_receipts(self.ci, self.release)
        self.assertIn("./sdks/python", next(s for s in steps(jobs(self.ci)["release-image-smoke"])
                                           if "pip install awscli" in s))
        self.assertIn("pip install awscli ./sdks/python", jobs(self.release)["release"])

    def test_workflow_regressions_are_rejected(self):
        mutations = (
            (self.assert_early_gate, self.release.replace("    needs: contract\n", "", 1)),
            (self.assert_early_gate, self.release.replace("python3 -B scripts/check-release-publication.py", "true")),
            (self.assert_early_gate, self.release.replace("  contract:\n", "  contract:\n    continue-on-error: true\n")),
            (self.assert_serialized, self.release.replace("cancel-in-progress: false", "cancel-in-progress: true")),
            (self.assert_serialized, self.release.replace("format('refs/tags/{0}', inputs.release_tag)", "inputs.release_tag")),
        )
        for assertion, text in mutations:
            with self.subTest(assertion=assertion.__name__), self.assertRaises(AssertionError):
                assertion(text)
        for before, after in (("if-no-files-found: error", "if-no-files-found: warn"),
                              ("maskura-candidate-feedback-${{ matrix.suffix }}", "maskura-candidate-feedback"),
                              ("-${{ github.run_attempt }}", ""),
                               ("path: dist/candidate-feedback.json", "path: dist/missing.json"),
                               ("      - name: Retain candidate feedback receipt", "      - if: always()\n        name: Retain candidate feedback receipt"),
                               ("id: feedback-regressions", "id: wrong-producer"),
                               ("${{ !cancelled() && (steps.feedback-regressions.outcome == 'success' || steps.feedback-regressions.outcome == 'failure') }}", "${{ always() }}"),
                               ("steps.feedback-regressions.outcome == 'failure'", "steps.feedback-regressions.outcome == 'skipped'"),
                               ("!cancelled() && ", ""),
                              ("python3 -m pip install awscli ./sdks/python", "python3 -m pip install ./sdks/python"),
                              ("runs-on: ubuntu-24.04-arm", "runs-on: ubuntu-24.04")):
            with self.subTest(before=before), self.assertRaises(AssertionError):
                self.assert_dependencies_and_receipts(self.ci.replace(before, after), self.release)

    def test_offline_tests_run_in_existing_fmt_gate(self):
        fmt = jobs(self.ci)["fmt"]
        self.assertIn("python3 -B -m unittest discover -s tests -p 'test_release_publication.py'", fmt)


if __name__ == "__main__":
    unittest.main()
