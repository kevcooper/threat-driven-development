import io
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

from tests.helpers import RepoTestCase
from threat_tdd import claude_hooks, git_hooks

ZERO = "0" * 40


class ClaudeHookTests(RepoTestCase):
    def run_hook(self, event, payload):
        payload.setdefault("cwd", self.root)
        payload.setdefault("session_id", "s1")
        out = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO(json.dumps(payload))), mock.patch("sys.stdout", out):
            code = claude_hooks.main(event)
        self.assertEqual(code, 0)
        text = out.getvalue().strip()
        return json.loads(text) if text else None

    def test_session_start_context(self):
        out = self.run_hook("session-start", {})
        self.assertIn("Threat Driven Development is active", out["hookSpecificOutput"]["additionalContext"])

    def test_stop_ignores_untouched_session(self):
        self.write("app.py", "print('pre-existing change')\n")
        self.run_hook("session-start", {})
        self.assertIsNone(self.run_hook("stop", {}))

    def test_stop_blocks_when_session_changed_code(self):
        self.run_hook("session-start", {})
        self.write("app.py", "print('agent change')\n")
        out = self.run_hook("stop", {})
        self.assertEqual(out["decision"], "block")
        self.assertIsNone(self.run_hook("stop", {"stop_hook_active": True}))
        self.tdd("declare", "Changes a print statement only; no new inputs, outputs or boundaries.")
        self.assertIsNone(self.run_hook("stop", {}))

    def test_stop_warn_mode(self):
        cfg = self.read_json(".tdd/config.json")
        cfg["hooks"]["claude_stop"] = "warn"
        self.write_json(".tdd/config.json", cfg)
        out = self.run_hook("stop", {})
        self.assertIn("systemMessage", out)

    def test_post_tool_use_validates_model(self):
        self.write("threats/demo.tc.json", '{"threats": [{"id": "a"}]}')
        out = self.run_hook("post-tool-use", {"tool_name": "Write",
                                              "tool_input": {"file_path": "threats/demo.tc.json"}})
        self.assertEqual(out["decision"], "block")
        self.assertIsNone(self.run_hook("post-tool-use", {"tool_name": "Write",
                                                          "tool_input": {"file_path": "app.py"}}))

    def test_post_tool_use_reformats_to_threat_composer_form(self):
        path = "threats/demo.tc.json"
        self.write(path, json.dumps(self.read_json(path), indent=4, sort_keys=True))
        out = self.run_hook("post-tool-use", {"tool_name": "Edit", "tool_input": {"file_path": path}})
        self.assertIn("reformatted", out["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(self.tdd("fmt", "--check"), 0)
        self.assertIsNone(self.run_hook("post-tool-use", {"tool_name": "Edit", "tool_input": {"file_path": path}}))

    def test_post_tool_use_blocks_text_threat_composer_would_mangle(self):
        self.tdd("add-threat", "--source", "user", "--action", "read data")
        path = "threats/demo.tc.json"
        data = self.read_json(path)
        data["threats"][0]["threatAction"] = "read & write <thing>"
        self.write_json(path, data)
        before = open(os.path.join(self.root, path)).read()
        out = self.run_hook("post-tool-use", {"tool_name": "Edit", "tool_input": {"file_path": path}})
        self.assertEqual(out["decision"], "block")
        self.assertIn("Rephrase", out["reason"])
        self.assertEqual(open(os.path.join(self.root, path)).read(), before)  # not silently rewritten

    def test_uninitialized_repo_is_silent(self):
        os.remove(os.path.join(self.root, ".tdd/config.json"))
        self.assertIsNone(self.run_hook("session-start", {}))
        self.write("app.py", "x\n")
        self.assertIsNone(self.run_hook("stop", {}))


class GitHookTests(RepoTestCase):
    def test_install_and_chain_existing_hook(self):
        hooks = git_hooks.hooks_dir(self.root)
        os.makedirs(hooks, exist_ok=True)
        with open(os.path.join(hooks, "pre-push"), "w") as fh:
            fh.write("#!/bin/sh\nexit 0\n")
        git_hooks.install(self.root)
        self.assertTrue(os.path.exists(os.path.join(hooks, "pre-push.pre-tdd")))
        with open(os.path.join(hooks, "pre-push")) as fh:
            self.assertIn(git_hooks.MARKER, fh.read())
        git_hooks.uninstall(self.root)
        with open(os.path.join(hooks, "pre-push")) as fh:
            self.assertNotIn(git_hooks.MARKER, fh.read())

    def push_line(self):
        return f"refs/heads/feature {self.git('rev-parse', 'HEAD').strip()} refs/heads/feature {ZERO}\n"

    def test_pre_push_blocks_then_passes(self):
        self.write("app.py", "print('x')\n")
        self.git("commit", "-qam", "code only")
        with mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(git_hooks.pre_push(self.root, [], self.push_line()), 1)
        self.git("commit", "-q", "--amend", "-m",
                 "code\n\nNo-Threat-Delta: Changes greeting text only; nothing security relevant.")
        self.assertEqual(git_hooks.pre_push(self.root, [], self.push_line()), 0)

    def test_commit_msg_hook_end_to_end(self):
        cfg = self.read_json(".tdd/config.json")
        cfg["hooks"]["commit_msg"] = "block"
        self.write_json(".tdd/config.json", cfg)
        self.git("commit", "-qam", "config\n\nNo-Threat-Delta: Tightens the commit-msg hook from warn to block.")
        env = dict(os.environ, TDD_BIN=os.path.join(os.path.dirname(os.path.dirname(__file__)), "bin", "tdd"))
        git_hooks.install(self.root)
        self.write("app.py", "print('y')\n")
        self.git("add", "app.py")
        proc = subprocess.run(["git", "commit", "-qm", "nope"], cwd=self.root, env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertNotEqual(proc.returncode, 0, proc.stderr)
        proc = subprocess.run(
            ["git", "commit", "-qm", "ok\n\nNo-Threat-Delta: Changes greeting text only; nothing security relevant."],
            cwd=self.root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
