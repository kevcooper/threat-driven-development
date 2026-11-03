import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest

from threat_tdd import cli


class RepoTestCase(unittest.TestCase):
    """Each test gets a fresh git repo on 'main' with tdd initialized and committed."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="tdd-test-")
        self.root = os.path.realpath(self.tmp)
        self._cwd = os.getcwd()
        os.chdir(self.root)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "t@example.com")
        self.git("config", "user.name", "Test")
        self.git("config", "commit.gpgsign", "false")
        self.write("app.py", "print('hi')\n")
        self.git("add", ".")
        self.git("commit", "-qm", "init")
        self.tdd("init", "--name", "Demo")
        self.git("add", "-A")
        self.git("commit", "-qm", "tdd init")
        self.git("checkout", "-qb", "feature")

    def tearDown(self):
        os.chdir(self._cwd)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout

    def write(self, path, text):
        full = os.path.join(self.root, path)
        os.makedirs(os.path.dirname(full) or ".", exist_ok=True)
        with open(full, "w") as fh:
            fh.write(text)

    def read_json(self, path):
        with open(os.path.join(self.root, path)) as fh:
            return json.load(fh)

    def write_json(self, path, data):
        self.write(path, json.dumps(data, indent=2))

    def tdd(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main(list(args))
            except SystemExit as exc:
                code = exc.code if isinstance(exc.code, int) else 1
                err.write(str(exc.code))
        self.last_out, self.last_err = out.getvalue(), err.getvalue()
        return code

    def tdd_json(self, *args):
        self.tdd(*args, "--json")
        return json.loads(self.last_out)

    def set_checks(self, checks):
        cfg = self.read_json(".tdd/config.json")
        cfg["checks"] = checks
        self.write_json(".tdd/config.json", cfg)

    def add_green_threat(self):
        self.set_checks({"ok": {"run": "exit 0"}})
        self.tdd("add-threat", "--source", "external actor", "--action", "forge a request",
                 "--impact", "unauthorized writes", "--goal", "integrity", "--asset", "orders")
        self.tdd("add-mitigation", "--threat", "T-1", "--content", "CSRF tokens", "--check", "ok")
        # The check passes, so the mitigation is implemented: resolve it in the same change.
        self.tdd("check", "--resolve")
