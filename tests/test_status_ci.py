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

    def test_planned_vs_resolved_failing_checks(self):
        self.set_checks({"ok": {"run": "exit 0"}, "bad": {"run": "exit 1"}})
        self.tdd("add-threat", "--source", "user", "--action", "x")
        self.tdd("add-mitigation", "--threat", "T-1", "--content", "done", "--check", "ok")
        self.tdd("add-mitigation", "--threat", "T-1", "--content", "planned", "--check", "bad")
        # planned mitigation's failing check doesn't override a verified one
        self.assertEqual(self.tdd_json("status", "--run-checks")["threats"][0]["state"], "green")
        data = self.read_json("threats/demo.tc.json")
        for m in data["mitigations"]:
            m["status"] = "mitigationResolved"
        self.write_json("threats/demo.tc.json", data)
        # once resolved, the same failing check is a regression
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


class MitigationStatusTests(RepoTestCase):
    def mitigation_status(self, n=1):
        data = self.read_json("threats/demo.tc.json")
        return [m for m in data["mitigations"] if m["numericId"] == n][0]["status"]

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-qm", "change")

    def setUp(self):
        super().setUp()
        self.set_checks({"ok": {"run": "exit 0"}, "bad": {"run": "exit 1"}})
        self.write("app.py", "print('csrf')\n")
        self.tdd("add-threat", "--source", "user", "--action", "forge a request")
        self.tdd("add-mitigation", "--threat", "T-1", "--content", "CSRF tokens", "--check", "ok")
        self.tdd("add-mitigation", "--threat", "T-1", "--content", "Rate limits", "--check", "bad")

    def test_check_resolve_flips_only_passing(self):
        self.tdd("check")
        self.assertIn("checks pass (ok)", self.last_out)
        self.assertEqual(self.mitigation_status(1), "mitigationIdentified")  # report only
        self.tdd("check", "--resolve")
        self.assertIn("M-1 -> mitigationResolved", self.last_out)
        self.assertEqual(self.mitigation_status(1), "mitigationResolved")
        self.assertEqual(self.mitigation_status(2), "mitigationIdentified")  # not implemented yet
        self.assertEqual(self.tdd("fmt", "--check"), 0)
        self.tdd("check", "--resolve")
        self.assertNotIn("->", self.last_out)

    def test_ci_requires_status_flip_with_implementation(self):
        self.commit()
        self.assertEqual(self.tdd("ci", "--base", "main", "--summary", "/dev/null"), 1)
        self.assertIn("M-1 checks pass (ok) but its status is mitigationIdentified", self.last_out)
        self.tdd("check", "--resolve")
        self.commit()
        self.assertEqual(self.tdd("ci", "--base", "main", "--summary", "/dev/null"), 0, self.last_out)

    def test_ci_rejects_resolved_mitigation_with_failing_check(self):
        self.tdd("check", "--resolve")
        data = self.read_json("threats/demo.tc.json")
        for m in data["mitigations"]:
            m["status"] = "mitigationResolved"
        self.write_json("threats/demo.tc.json", data)
        self.tdd("fmt")
        self.commit()
        self.assertEqual(self.tdd("ci", "--base", "main", "--summary", "/dev/null"), 1)
        self.assertIn("M-2 is mitigationResolved but its check failed (bad)", self.last_out)

    def test_policy_warn(self):
        cfg = self.read_json(".tdd/config.json")
        cfg["policy"]["mitigation_status"] = "warn"
        self.write_json(".tdd/config.json", cfg)
        self.commit()
        self.assertEqual(self.tdd("ci", "--base", "main", "--summary", "/dev/null", "--trust-head-config"), 0,
                         self.last_out)


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
