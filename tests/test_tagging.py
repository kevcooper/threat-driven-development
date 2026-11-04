"""Annotated git tags on the commits that resolve mitigations."""

import json
import os
import subprocess
import tempfile

from tests.helpers import RepoTestCase
from threat_tdd import config as config_mod
from threat_tdd import git_hooks, tagging

PATH = "threats/demo.tc.json"


class TaggingTests(RepoTestCase):
    def setUp(self):
        super().setUp()
        self.set_checks({"ok": {"run": "test -f implemented"}})
        self.tdd("add-threat", "--source", "user", "--action", "forge a request", "--priority", "High",
                 "--strategy", "mitigate")
        self.tdd("add-mitigation", "--threat", "T-1", "--content", "CSRF tokens", "--check", "ok")
        self.commit("plan the mitigation")  # check fails: nothing to tag yet

    def commit(self, msg, amend=False):
        self.git("add", "-A")
        self.git("commit", "-q", *(["--amend"] if amend else []), "-m", msg)
        return self.git("rev-parse", "HEAD").strip()

    def implement(self, msg="implement CSRF tokens"):
        self.write("implemented", "yes\n")
        self.tdd("sync")
        return self.commit(msg)

    def tags(self):
        return self.git("tag", "-l").split()

    def mid(self, path=PATH):
        """The tag name for the model's first mitigation: tdd/<model>/M-<n>."""
        name = os.path.basename(path)[: -len(".tc.json")]
        return f"tdd/{name}/M-{self.read_json(path)['mitigations'][0]['numericId']}"

    def cfg(self):
        return config_mod.load(self.root)

    def tag_commit(self, tag):
        return self.git("rev-parse", f"{tag}^{{commit}}").strip()

    def test_tag_command_tags_resolving_commit(self):
        sha = self.implement()
        self.assertEqual(self.tdd("tag"), 0)
        mid = self.mid()
        self.assertIn(f"created      {mid}", self.last_out)
        self.assertEqual(self.tags(), [mid])
        self.assertEqual(self.tag_commit(mid), sha)
        body = self.git("tag", "-l", "--format=%(contents)", mid)
        self.assertIn("M-1 resolved: CSRF tokens", body)
        self.assertIn("Threat: T-1 (High): A user can forge a request", body)
        self.assertIn("Checks: ok", body)
        self.assertIn("Priority: high", body)
        self.assertEqual(mid, "tdd/demo/M-1")
        self.assertIn(f"Mitigation id: {self.read_json(PATH)['mitigations'][0]['id']}", body)
        self.assertEqual(self.git("cat-file", "-t", mid).strip(), "tag")  # annotated
        self.tdd("tag")
        self.assertIn("exists", self.last_out)

    def test_non_resolving_commit_gets_no_tag(self):
        self.write("app.py", "changed\n")
        self.commit("unrelated")
        self.tdd("tag")
        self.assertIn("no mitigations resolved", self.last_out)
        self.assertEqual(self.tags(), [])

    def test_post_commit_hook(self):
        git_hooks.install(self.root)
        env = dict(os.environ, TDD_BIN=os.path.join(os.path.dirname(os.path.dirname(__file__)), "bin", "tdd"))
        self.write("implemented", "yes\n")
        self.tdd("sync")
        self.git("add", "-A")
        proc = subprocess.run(["git", "commit", "-qm", "implement\n\nNo-Threat-Delta: test fixture commit only."],
                              cwd=self.root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(f"created tag {self.mid()}", proc.stderr)
        self.assertEqual(self.tag_commit(self.mid()), self.git("rev-parse", "HEAD").strip())
        self.assertEqual(self.git("config", "push.followTags").strip(), "true")

    def test_amend_moves_tag(self):
        self.implement()
        self.tdd("tag")
        self.write("implemented", "yes, amended\n")
        amended = self.commit("implement CSRF tokens (amended)", amend=True)
        self.tdd("tag")
        self.assertIn("moved", self.last_out)
        self.assertEqual(self.tag_commit(self.mid()), amended)
        self.assertEqual(self.tags(), [self.mid()])

    def test_regression_then_resolve_again_gets_suffix(self):
        first = self.implement()
        self.tdd("tag")
        os.remove(os.path.join(self.root, "implemented"))
        self.tdd("progress", "--mitigation", "M-1", "in-progress")
        self.commit("regressed")
        second = self.implement("fix it again")
        self.tdd("tag")
        self.assertEqual(self.tag_commit(self.mid()), first)
        self.assertEqual(self.tag_commit(self.mid() + "-r2"), second)

    def test_merge_commit_keeps_branch_tag(self):
        main_before = self.git("rev-parse", "main").strip()
        work = self.implement()
        self.tdd("tag")
        self.git("checkout", "-q", "main")
        self.git("merge", "-q", "--no-ff", "-m", "merge feature", "feature")
        self.tdd("tag", "--base", main_before, "--head", "main")
        self.assertIn("exists", self.last_out)
        self.assertEqual(self.tags(), [self.mid()])
        self.assertEqual(self.tag_commit(self.mid()), work)

    def test_squash_merge_moves_tag_to_main(self):
        main_before = self.git("rev-parse", "main").strip()
        self.implement()
        self.tdd("tag")
        self.git("checkout", "-q", "main")
        self.git("merge", "-q", "--squash", "feature")
        squashed = self.commit("squashed feature")
        self.tdd("tag", "--base", main_before, "--head", "main")
        self.assertIn("moved", self.last_out)
        self.assertEqual(self.tag_commit(self.mid()), squashed)

    def test_dry_run_and_disable(self):
        self.implement()
        self.tdd("tag", "--dry-run")
        self.assertIn("would-create", self.last_out)
        self.assertEqual(self.tags(), [])
        cfg = self.read_json(".tdd/config.json")
        cfg["tags"] = {"mitigations": False}
        self.write_json(".tdd/config.json", cfg)
        self.assertEqual(git_hooks.post_commit(self.root, []), 0)
        self.assertEqual(self.tags(), [])

    def test_name_collision_across_models(self):
        cfg = self.read_json(".tdd/config.json")
        cfg["models"] = ["threats/**/*.tc.json"]
        cfg["checks"]["ok2"] = {"run": "test -f implemented"}
        self.write_json(".tdd/config.json", cfg)
        os.makedirs(os.path.join(self.root, "threats/other"), exist_ok=True)
        self.write("threats/other/demo.tc.json", open(os.path.join(self.root, PATH)).read())
        data = self.read_json("threats/other/demo.tc.json")
        import uuid
        mapping = {m["id"]: str(uuid.uuid4()) for m in data["mitigations"]}
        mapping.update({t["id"]: str(uuid.uuid4()) for t in data["threats"]})
        for item in data["mitigations"] + data["threats"]:
            item["id"] = mapping[item["id"]]
        for link in data["mitigationLinks"]:
            link["mitigationId"], link["linkedId"] = mapping[link["mitigationId"]], mapping[link["linkedId"]]
        self.write_json("threats/other/demo.tc.json", data)
        self.tdd("fmt")
        self.commit("second model")
        self.implement()
        self.tdd("tag")
        # both models are called "demo": the first M-1 gets demo/M-1, the other is skipped
        self.assertEqual(self.tags(), ["tdd/demo/M-1"])
        self.assertIn("already marks a different mitigation", self.last_out)

    def test_model_names_are_ref_safe(self):
        cfg = self.cfg()
        cases = {
            "threats/billing.tc.json": "tdd/billing/M-3",
            "threats/My Service!.tc.json": "tdd/My-Service/M-3",
            "threats/..evil.tc.json": "tdd/evil/M-3",
            "x/--force.tc.json": "tdd/force/M-3",
            "x/$(id).tc.json": "tdd/id/M-3",
            "x/a..b.tc.json": "tdd/a.b/M-3",
            "x/name.lock.tc.json": "tdd/name/M-3",
        }
        for path, tag in cases.items():
            self.assertEqual(tagging.base_tag(cfg, path, 3), tag, path)
            self.assertTrue(tagging._valid_ref(self.root, tag), tag)
        for bad in ["3", 1.5, None, True, "M-3"]:
            self.assertIsNone(tagging.base_tag(cfg, "threats/billing.tc.json", bad), bad)

    def test_non_integer_numeric_id_skipped_with_warning(self):
        data = self.read_json(PATH)
        data["mitigations"][0]["numericId"] = 1.5
        data["mitigations"][0]["status"] = "mitigationResolved"
        self.write(PATH, json.dumps(data))
        self.write("implemented", "yes\n")
        self.commit("odd numericId")
        self.assertEqual(self.tdd("tag"), 0)
        self.assertIn("skipped", self.last_out)
        self.assertIn("isn't a whole number", self.last_out)
        self.assertEqual(self.tags(), [])

    def test_foreign_tag_is_left_alone(self):
        self.git("tag", "tdd/demo/M-1")  # someone else's lightweight tag
        self.implement()
        self.tdd("tag")
        self.assertIn("wasn't created by tdd", self.last_out)
        self.assertEqual(self.git("cat-file", "-t", "tdd/demo/M-1").strip(), "commit")  # untouched

    def test_prefix(self):
        cfg = self.read_json(".tdd/config.json")
        cfg["tags"] = {"prefix": "mitigation"}
        self.write_json(".tdd/config.json", cfg)
        self.implement()
        self.tdd("tag")
        self.assertEqual(self.tags(), ["mitigation/demo/M-1"])
        cfg["tags"] = {"prefix": ""}
        self.write_json(".tdd/config.json", cfg)
        self.assertEqual(tagging.base_tag(self.cfg(), PATH, 1), "demo/M-1")

    def test_model_text_cannot_reach_a_shell(self):
        data = self.read_json(PATH)
        data["mitigations"][0]["content"] = "CSRF $(touch pwned) `touch pwned2`; rm -rf ~ --force"
        self.write_json(PATH, data)
        self.tdd("fmt")
        self.commit("hostile text")
        self.implement()
        self.assertEqual(self.tdd("tag"), 0, self.last_err)
        body = self.git("tag", "-l", "--format=%(contents)", self.mid())
        self.assertIn("$(touch pwned) `touch pwned2`", body)
        self.assertFalse(os.path.exists(os.path.join(self.root, "pwned")))
        self.assertFalse(os.path.exists(os.path.join(self.root, "pwned2")))

    def test_push(self):
        remote = tempfile.mkdtemp(prefix="tdd-remote-")
        subprocess.run(["git", "init", "-q", "--bare", remote], check=True)
        self.git("remote", "add", "origin", remote)
        self.git("push", "-q", "origin", "feature")
        self.implement()
        self.git("push", "-q", "origin", "feature")
        self.assertEqual(self.tdd("tag", "--push"), 0, self.last_err)
        remote_tags = subprocess.run(["git", "tag", "-l"], cwd=remote, stdout=subprocess.PIPE, text=True).stdout
        self.assertIn(self.mid(), remote_tags)
