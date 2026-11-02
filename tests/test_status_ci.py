import unittest

from tests.helpers import RepoTestCase


class StatusTests(RepoTestCase):
    def test_lifecycle_red_unverified_green(self):
        self.set_checks({"ok": {"run": "exit 0"}})
        self.tdd("add-threat", "--source", "user", "--action", "x")
        self.assertEqual(self.tdd_json("status")["counts"]["red"], 1)
        self.tdd("add-mitigation", "--threat", "T-1", "--content", "fix")
        self.assertIn("no check", self.tdd_json("status")["threats"][0]["reason"])
        self.tdd("link", "--mitigation", "M-1", "--check", "ok")
        self.assertEqual(self.tdd_json("status")["threats"][0]["state"], "unverified")
        out = self.tdd_json("status", "--run-checks")
        self.assertEqual(out["threats"][0]["state"], "green")

    def test_failing_check_is_red(self):
        self.set_checks({"bad": {"run": "exit 3"}})
        self.tdd("add-threat", "--source", "user", "--action", "x")
        self.tdd("add-mitigation", "--threat", "T-1", "--content", "fix", "--check", "bad")
        t = self.tdd_json("status", "--run-checks")["threats"][0]
        self.assertEqual((t["state"], t["failing_checks"]), ("red", ["bad"]))

    def test_waive_requires_reason(self):
        self.tdd("add-threat", "--source", "user", "--action", "x")
        self.assertEqual(self.tdd("waive", "--threat", "T-1", "ok"), 1)
        self.assertEqual(self.tdd("waive", "--threat", "T-1", "Only reachable from the build host, which is out of scope."), 0)
        self.assertEqual(self.tdd_json("status")["threats"][0]["state"], "waived")
        self.assertEqual(self.tdd("validate"), 0)

    def test_wont_do_mitigation_does_not_count(self):
        self.set_checks({"ok": {"run": "exit 0"}})
        self.tdd("add-threat", "--source", "user", "--action", "x")
        self.tdd("add-mitigation", "--threat", "T-1", "--content", "fix", "--check", "ok")
        data = self.read_json("threats/demo.tc.json")
        data["mitigations"][0]["status"] = "mitigationResolvedWillNotAction"
        self.write_json("threats/demo.tc.json", data)
        self.assertEqual(self.tdd_json("status", "--run-checks")["threats"][0]["state"], "red")


class CITests(RepoTestCase):
    def commit(self, msg="change"):
        self.git("add", "-A")
        self.git("commit", "-qm", msg)

    def test_new_green_threat_passes(self):
        self.write("app.py", "print('csrf')\n")
        self.add_green_threat()
        self.commit()
        self.assertEqual(self.tdd("ci", "--base", "main", "--summary", "/dev/null"), 0, self.last_out)

    def test_new_red_threat_blocks(self):
        self.write("app.py", "print('csrf')\n")
        self.tdd("add-threat", "--source", "user", "--action", "x")
        self.commit()
        self.assertEqual(self.tdd("ci", "--base", "main", "--summary", "/dev/null"), 1)
        self.assertIn("blocking", self.last_out)

    def test_preexisting_red_threat_only_warns(self):
        self.git("checkout", "-q", "main")
        self.tdd("add-threat", "--source", "user", "--action", "x")
        self.commit("backlog threat")
        self.git("checkout", "-qb", "f2")
        self.write("app.py", "print('other')\n")
        self.tdd("declare", "Changes greeting text only; no inputs, outputs or permissions change.")
        self.commit()
        self.assertEqual(self.tdd("ci", "--base", "main", "--summary", "/dev/null"), 0, self.last_out)

    def test_head_cannot_weaken_policy(self):
        self.write("app.py", "print('csrf')\n")
        self.tdd("add-threat", "--source", "user", "--action", "x")
        cfg = self.read_json(".tdd/config.json")
        cfg["policy"] = {"red": "warn"}
        self.write_json(".tdd/config.json", cfg)
        self.commit()
        self.assertEqual(self.tdd("ci", "--base", "main", "--summary", "/dev/null"), 1)
        self.assertIn("takes effect after merge", self.last_out)
        self.assertEqual(self.tdd("ci", "--base", "main", "--summary", "/dev/null", "--trust-head-config"), 0)

    def test_code_without_delta_fails(self):
        self.write("app.py", "print('x')\n")
        self.commit()
        self.assertEqual(self.tdd("ci", "--base", "main", "--summary", "/dev/null"), 1)


if __name__ == "__main__":
    unittest.main()
