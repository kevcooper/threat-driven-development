"""Tests that serve as checks for this repository's own threat model (threats/tdd.tc.json)."""

import io
import json
import os
import re
import unittest
from unittest import mock

from tests.helpers import RepoTestCase
from threat_tdd import checks as checks_mod
from threat_tdd import claude_hooks, config as config_mod
from threat_tdd.declare import judge

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ActionInjectionTests(unittest.TestCase):
    """T: PR text interpolated into a run: script executes as shell in CI."""

    def test_run_script_has_no_expression_interpolation(self):
        with open(os.path.join(REPO, "action.yml")) as fh:
            text = fh.read()
        run_blocks = re.findall(r"run: \|\n((?:\s{8}.*\n?)+)", text)
        self.assertTrue(run_blocks, "expected a run: block in action.yml")
        for block in run_blocks:
            self.assertNotIn("${{", block, "use env: to pass expressions into run scripts")

    def test_pr_body_only_via_env(self):
        with open(os.path.join(REPO, "action.yml")) as fh:
            lines = [l for l in fh if "pull_request.body" in l]
        self.assertTrue(lines)
        for line in lines:
            self.assertRegex(line.strip(), r"^TDD_PR_BODY: \$\{\{ github\.event\.pull_request\.body \}\}$")


class DeclarationQualityTests(unittest.TestCase):
    """T: a boilerplate declaration bypasses threat review."""

    def test_boilerplate_and_short_text_rejected(self):
        for text in ["n/a", "None.", "trivial", "no security impact", "  ", "refactor"]:
            self.assertIsNotNone(judge(text, 30), text)
        self.assertIsNone(judge("Renames internal helpers in the CSV exporter; same inputs and outputs.", 30))


class ChecksByNameTests(RepoTestCase):
    """T: shell placed in a threat model file runs in CI."""

    def test_check_tag_never_executes_as_shell(self):
        marker = os.path.join(self.root, "pwned")
        cfg = config_mod.load(self.root)
        result = checks_mod.run_check(cfg, f"x; touch {marker}")
        self.assertEqual(result.outcome, checks_mod.MISSING)
        self.assertFalse(os.path.exists(marker))


class HooksDoNotRunChecksTests(RepoTestCase):
    """T: opening an untrusted repo with the plugin runs repo-defined commands."""

    def test_session_start_and_stop_never_run_checks(self):
        self.set_checks({"evil": {"run": "touch pwned"}})
        self.tdd("add-threat", "--source", "user", "--action", "x")
        self.tdd("add-mitigation", "--threat", "T-1", "--content", "m", "--check", "evil")
        self.write("app.py", "changed\n")
        boom = mock.Mock(side_effect=AssertionError("hook ran a check"))
        with mock.patch.object(checks_mod, "run_check", boom), mock.patch.object(checks_mod, "run_many", boom):
            for event in ("session-start", "stop", "post-tool-use"):
                payload = {"cwd": self.root, "session_id": "s",
                           "tool_input": {"file_path": "threats/demo.tc.json"}}
                with mock.patch("sys.stdin", io.StringIO(json.dumps(payload))), \
                        mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", io.StringIO()) as err:
                    claude_hooks.main(event)
                self.assertNotIn("hook ran a check", err.getvalue())
        self.assertFalse(os.path.exists(os.path.join(self.root, "pwned")))


class CIBackstopTests(unittest.TestCase):
    """T: a developer skips local hooks with --no-verify."""

    def test_repo_workflow_runs_gate_on_pull_requests(self):
        with open(os.path.join(REPO, ".github", "workflows", "ci.yml")) as fh:
            text = fh.read()
        self.assertIn("pull_request:", text)
        self.assertIn("uses: ./", text)
        self.assertIn("fetch-depth: 0", text)


if __name__ == "__main__":
    unittest.main()
