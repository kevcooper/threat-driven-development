import json
import unittest

from tests.helpers import RepoTestCase


class GateTests(RepoTestCase):
    def test_no_changes_passes(self):
        self.assertEqual(self.tdd("gate"), 0)

    def test_code_change_without_delta_fails(self):
        self.write("app.py", "print('changed')\n")
        self.assertEqual(self.tdd("gate"), 1)
        self.assertIn("without a threat model delta", self.last_out)

    def test_ignored_paths_do_not_require_delta(self):
        self.write("docs/guide.md", "hello\n")
        self.write("NOTES.md", "hello\n")
        self.assertEqual(self.tdd("gate"), 0)

    def test_config_change_is_code(self):
        self.set_checks({"x": {"run": "true"}})
        self.assertEqual(self.tdd("gate"), 1)

    def test_threat_delta_passes(self):
        self.write("app.py", "print('changed')\n")
        self.tdd("add-threat", "--source", "user", "--action", "upload a huge file", "--impact", "outage")
        self.assertEqual(self.tdd("gate"), 0)
        self.assertIn("added   threat T-1", self.last_out)

    def test_formatting_only_change_is_not_a_delta(self):
        self.write("app.py", "print('changed')\n")
        path = "threats/demo.tc.json"
        data = self.read_json(path)
        self.write(path, json.dumps(data, indent=4, sort_keys=True))
        self.assertEqual(self.tdd("gate"), 1)
        self.assertIn("formatting only", self.last_out)

    def test_declaration_file(self):
        self.write("app.py", "print('changed')\n")
        self.assertEqual(self.tdd("declare", "Renames a local variable; no change to inputs or boundaries."), 0)
        self.assertEqual(self.tdd("gate"), 0)
        self.assertIn("declaration", self.last_out)

    def test_boilerplate_declaration_rejected(self):
        self.assertEqual(self.tdd("declare", "n/a"), 1)
        self.assertEqual(self.tdd("declare", "too short"), 1)

    def test_commit_trailer(self):
        self.write("app.py", "print('changed')\n")
        self.git("commit", "-qam", "change\n\nNo-Threat-Delta: none")
        self.assertEqual(self.tdd("gate", "--head", "HEAD"), 1)
        self.assertIn("boilerplate", self.last_out)
        self.git("commit", "-q", "--amend", "-m",
                 "change\n\nNo-Threat-Delta: Only changes log wording; no new data is logged or exposed.")
        self.assertEqual(self.tdd("gate", "--head", "HEAD"), 0)

    def test_pr_body_declaration(self):
        import os
        self.write("app.py", "print('changed')\n")
        self.git("commit", "-qam", "change")
        os.environ["TEST_PR_BODY"] = "Summary\n\nNo-Threat-Delta: Pure refactor of the formatter; behaviour is unchanged."
        try:
            self.assertEqual(self.tdd("gate", "--head", "HEAD", "--pr-body-env", "TEST_PR_BODY"), 0)
        finally:
            del os.environ["TEST_PR_BODY"]

    def test_invalid_model_fails_gate(self):
        self.write("threats/demo.tc.json", "{not json")
        self.assertEqual(self.tdd("gate"), 1)
        self.assertIn("invalid", self.last_out)

    def test_staged_mode_ignores_unstaged(self):
        self.write("app.py", "print('changed')\n")
        self.assertEqual(self.tdd("gate", "--staged"), 0)
        self.git("add", "app.py")
        self.assertEqual(self.tdd("gate", "--staged"), 1)

    def test_delta_json(self):
        self.tdd("add-threat", "--source", "user", "--action", "x")
        out = self.tdd_json("delta")
        self.assertEqual([c["op"] for c in out["changes"]], ["added"])


if __name__ == "__main__":
    unittest.main()
