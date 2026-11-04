"""Each mitigation carries a priority:<level> tag: the highest Priority of its linked threats."""

import io
import json
from unittest import mock

from tests.helpers import RepoTestCase
from threat_tdd import claude_hooks

PATH = "threats/demo.tc.json"


class PriorityTagTests(RepoTestCase):
    def mit(self, n=1):
        return [m for m in self.read_json(PATH)["mitigations"] if m["numericId"] == n][0]

    def setUp(self):
        super().setUp()
        self.set_checks({"ok": {"run": "exit 0"}})
        self.tdd("add-threat", "--source", "user", "--action", "read logs", "--priority", "Low")
        self.tdd("add-threat", "--source", "user", "--action", "delete logs", "--priority", "Medium")
        self.tdd("add-threat", "--source", "admin", "--action", "wipe the database", "--priority", "High")

    def test_highest_linked_priority(self):
        self.tdd("add-mitigation", "--threat", "T-1", "--threat", "T-2", "--content", "Audit log access",
                 "--check", "ok")
        self.assertEqual(self.mit()["tags"], ["check:ok", "priority:medium"])
        self.tdd("link", "--mitigation", "M-1", "--threat", "T-3")
        self.assertEqual(self.mit()["tags"], ["check:ok", "priority:high"])  # one tag, replaced
        self.assertEqual(self.tdd("lint"), 0, self.last_out)

    def test_no_tag_without_prioritized_threats(self):
        self.tdd("add-threat", "--source", "bot", "--action", "scrape pages")  # no Priority
        self.tdd("add-mitigation", "--threat", "T-4", "--content", "Rate limit")
        self.tdd("add-mitigation", "--content", "Unlinked control")
        self.assertEqual(self.mit(1)["tags"], [])
        self.assertEqual(self.mit(2)["tags"], [])

    def test_not_applicable_threats_dont_count(self):
        self.tdd("add-mitigation", "--threat", "T-1", "--threat", "T-3", "--content", "Backups")
        self.assertIn("priority:high", self.mit()["tags"])
        self.tdd("dismiss", "--threat", "T-3", "There is no database in this deployment at all.")
        self.assertEqual(self.mit()["tags"], ["priority:low"])

    def test_stale_tag_is_a_lint_error_and_sync_fixes_it(self):
        self.tdd("add-mitigation", "--threat", "T-1", "--content", "Audit log access")
        data = self.read_json(PATH)
        t1 = [t for t in data["threats"] if t["numericId"] == 1][0]
        for entry in t1["metadata"]:
            if entry["key"] == "Priority":
                entry["value"] = "High"  # someone raises the threat's priority in the editor
        self.write_json(PATH, data)
        self.tdd("fmt")
        self.assertEqual(self.tdd("lint"), 1)
        self.assertIn("TDD150", self.last_out)
        self.assertIn("should have priority:high", self.last_out)
        self.tdd("sync", "--dry-run", "--no-checks")
        self.assertIn("priority:low -> priority:high", self.last_out)
        self.assertEqual(self.mit()["tags"], ["priority:low"])  # dry run
        self.tdd("sync", "--no-checks")
        self.assertEqual(self.mit()["tags"], ["priority:high"])
        self.assertEqual(self.tdd("lint"), 0, self.last_out)

    def test_ci_fails_on_stale_tag(self):
        self.tdd("add-mitigation", "--threat", "T-3", "--content", "Backups")
        data = self.read_json(PATH)
        [m for m in data["mitigations"]][0]["tags"] = []
        self.write_json(PATH, data)
        self.tdd("fmt")
        self.write("app.py", "changed\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "x")
        self.assertEqual(self.tdd("ci", "--base", "main", "--summary", "/dev/null", "--no-checks"), 1)
        self.assertIn("should have priority:high", self.last_out)

    def test_hook_updates_tags_after_agent_edit(self):
        self.tdd("add-mitigation", "--threat", "T-1", "--content", "Audit log access")
        data = self.read_json(PATH)
        data["mitigationLinks"].append({"mitigationId": self.mit()["id"],
                                        "linkedId": [t for t in data["threats"] if t["numericId"] == 3][0]["id"]})
        self.write_json(PATH, data)
        payload = {"cwd": self.root, "session_id": "s", "tool_name": "Edit", "tool_input": {"file_path": PATH}}
        out = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO(json.dumps(payload))), mock.patch("sys.stdout", out):
            claude_hooks.main("post-tool-use")
        context = json.loads(out.getvalue())["hookSpecificOutput"]["additionalContext"]
        self.assertIn("M-1 priority tag priority:low -> priority:high", context)
        self.assertEqual(self.mit()["tags"], ["priority:high"])
