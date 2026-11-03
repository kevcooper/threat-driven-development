import unittest

from tests.helpers import RepoTestCase


class StatusTests(RepoTestCase):
    def test_lifecycle_red_unverified_green(self):
        self.set_checks({"ok": {"run": "exit 0"}})
        self.tdd("add-threat", "--source", "user", "--action", "x", "--strategy", "mitigate")
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
        self.tdd("add-threat", "--source", "user", "--action", "x", "--strategy", "mitigate")
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
        t = self.tdd_json("status")["threats"][0]
        self.assertEqual((t["state"], t["strategy"], t["declared_status"]), ("handled", "accept", "threatResolved"))
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
    def item(self, kind, n=1):
        data = self.read_json("threats/demo.tc.json")
        return [m for m in data[kind] if m["numericId"] == n][0]

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-qm", "change")

    def ci(self, *extra):
        return self.tdd("ci", "--base", "main", "--summary", "/dev/null", *extra)

    def setUp(self):
        super().setUp()
        self.set_checks({"ok": {"run": "exit 0"}, "bad": {"run": "exit 1"}})
        self.write("app.py", "print('csrf')\n")
        self.tdd("add-threat", "--source", "user", "--action", "forge a request", "--strategy", "mitigate")
        self.tdd("add-mitigation", "--threat", "T-1", "--content", "CSRF tokens", "--check", "ok")
        self.tdd("add-mitigation", "--threat", "T-1", "--content", "Rate limits", "--check", "bad")

    def test_sync_tracks_progress(self):
        self.tdd("sync", "--dry-run")
        self.assertIn("M-1 is mitigationIdentified but its checks pass (ok)", self.last_out)
        self.assertEqual(self.item("mitigations", 1)["status"], "mitigationIdentified")  # dry run
        self.tdd("sync")
        self.assertIn("M-1 mitigationIdentified -> mitigationResolved", self.last_out)
        self.assertIn("M-2 mitigationIdentified -> mitigationInProgress", self.last_out)
        self.assertIn("T-1 threatIdentified -> threatResolved", self.last_out)
        self.assertEqual(self.item("mitigations", 1)["status"], "mitigationResolved")
        self.assertEqual(self.item("mitigations", 2)["status"], "mitigationInProgress")
        self.assertEqual(self.item("threats", 1)["status"], "threatResolved")
        self.assertEqual(self.tdd("fmt", "--check"), 0)
        self.tdd("sync")
        self.assertIn("in sync", self.last_out)

    def test_check_resolve_is_sync(self):
        self.tdd("check", "--resolve")
        self.assertEqual(self.item("mitigations", 1)["status"], "mitigationResolved")

    def test_threat_not_resolved_without_strategy(self):
        data = self.read_json("threats/demo.tc.json")
        data["threats"][0]["tags"] = []
        self.write_json("threats/demo.tc.json", data)
        self.tdd("fmt")
        self.tdd("sync")
        self.assertEqual(self.item("threats", 1)["status"], "threatIdentified")
        t = self.tdd_json("status", "--run-checks")["threats"][0]
        self.assertEqual(t["state"], "red")
        self.assertIn("no risk strategy tag", t["reason"])

    def test_ci_requires_status_flip_with_implementation(self):
        self.commit()
        self.assertEqual(self.ci(), 1)
        self.assertIn("M-1 is mitigationIdentified but its checks pass (ok)", self.last_out)
        self.assertIn("T-1 is threatIdentified but it is green", self.last_out)
        self.tdd("sync")
        self.commit()
        self.assertEqual(self.ci(), 0, self.last_out)

    def test_ci_rejects_overclaims(self):
        self.tdd("sync")
        data = self.read_json("threats/demo.tc.json")
        for m in data["mitigations"]:
            m["status"] = "mitigationResolved"
        self.write_json("threats/demo.tc.json", data)
        self.tdd("fmt")
        self.commit()
        self.assertEqual(self.ci(), 1)
        self.assertIn("M-2 is mitigationResolved but its check failed (bad)", self.last_out)
        self.assertIn("T-1 is threatResolved but it is red", self.last_out)

    def test_policy_warn(self):
        cfg = self.read_json(".tdd/config.json")
        cfg["policy"]["status_sync"] = "warn"
        self.write_json(".tdd/config.json", cfg)
        self.commit()
        self.assertEqual(self.ci("--trust-head-config"), 0, self.last_out)


class StrategyTests(RepoTestCase):
    def threat(self):
        return self.read_json("threats/demo.tc.json")["threats"][0]

    def setUp(self):
        super().setUp()
        self.tdd("add-threat", "--source", "user", "--action", "read logs")

    def test_strategies(self):
        self.assertEqual(self.tdd("strategy", "--threat", "T-1", "accept"), 1)  # needs a reason
        self.assertEqual(self.tdd("strategy", "--threat", "T-1", "transfer",
                                  "Log storage is the hosting provider's responsibility under the DPA."), 0)
        t = self.threat()
        self.assertEqual(t["tags"], ["risk:transfer"])
        self.assertEqual(t["status"], "threatResolved")
        self.assertIn("Risk transferred:", t["metadata"][0]["value"])
        self.assertEqual(self.tdd_json("status")["threats"][0]["state"], "handled")
        # switching strategy replaces the tag, never stacks
        self.tdd("strategy", "--threat", "T-1", "mitigate")
        self.assertEqual(self.threat()["tags"], ["risk:mitigate"])

    def test_two_strategy_tags_is_red(self):
        data = self.read_json("threats/demo.tc.json")
        data["threats"][0]["tags"] = ["risk:accept", "risk:avoid"]
        self.write_json("threats/demo.tc.json", data)
        self.assertEqual(self.tdd_json("status")["threats"][0]["state"], "red")
        self.assertEqual(self.tdd("lint"), 1)
        self.assertIn("TDD111", self.last_out)

    def test_dismiss(self):
        self.assertEqual(self.tdd("dismiss", "--threat", "T-1", "n/a"), 1)
        self.assertEqual(self.tdd("dismiss", "--threat", "T-1", "The service has no log endpoint at all, so this is moot."), 0)
        t = self.tdd_json("status")["threats"][0]
        self.assertEqual((t["state"], t["declared_status"]), ("dismissed", "threatResolvedNotUseful"))

    def test_progress(self):
        self.set_checks({"bad": {"run": "exit 1"}})
        self.tdd("add-mitigation", "--threat", "T-1", "--content", "Redact logs", "--check", "bad")
        self.assertEqual(self.tdd("progress", "--mitigation", "M-1", "in-progress"), 0)
        self.assertEqual(self.tdd("progress", "--mitigation", "M-1", "resolved"), 1)  # check fails
        self.assertIn("not resolved", self.last_err)
        self.assertEqual(self.tdd("progress", "--mitigation", "M-1", "will-not-action"), 1)  # reason needed
        self.assertEqual(self.tdd("progress", "--mitigation", "M-1", "will-not-action",
                                  "Logs are already encrypted and access is audited elsewhere."), 0)
        m = self.read_json("threats/demo.tc.json")["mitigations"][0]
        self.assertEqual(m["status"], "mitigationResolvedWillNotAction")


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
