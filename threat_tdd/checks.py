"""Running the checks that mitigations link to.

Checks are named in ``.tdd/config.json`` and referenced from mitigations by name
(``check:<name>`` tag). Mitigations never carry raw shell commands, so the
threat model file cannot be used to smuggle commands into CI.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from typing import Dict, Iterable, Optional

from threat_tdd import gitutil
from threat_tdd.config import STATE_DIR, Config

PASS, FAIL, MISSING, ERROR = "pass", "fail", "missing", "error"


@dataclass
class CheckResult:
    name: str
    outcome: str  # pass | fail | missing | error
    seconds: float = 0.0
    output: str = ""
    command: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "outcome": self.outcome,
            "seconds": round(self.seconds, 2),
            "command": self.command,
            "output": self.output[-4000:],
        }


def run_check(cfg: Config, name: str) -> CheckResult:
    spec = cfg.checks.get(name)
    if not spec or not spec.get("run"):
        return CheckResult(name, MISSING, output=f"check '{name}' is not defined in .tdd/config.json")
    command = str(spec["run"])
    timeout = float(spec.get("timeout", 600))
    started = time.time()
    try:
        proc = subprocess.run(
            command,
            shell=True,
            cwd=cfg.root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            env={**os.environ, "TDD_CHECK": name},
        )
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
        return CheckResult(name, ERROR, time.time() - started, f"{out}\ntimed out after {timeout:g}s", command)
    outcome = PASS if proc.returncode == 0 else FAIL
    return CheckResult(name, outcome, time.time() - started, proc.stdout or "", command)


def run_many(cfg: Config, names: Iterable[str], echo=None) -> Dict[str, CheckResult]:
    results: Dict[str, CheckResult] = {}
    for name in sorted(set(names)):
        if echo:
            echo(f"running check {name} ...")
        results[name] = run_check(cfg, name)
        if echo:
            echo(f"  {results[name].outcome} ({results[name].seconds:.1f}s)")
    save_cache(cfg.root, results)
    return results


def _cache_path(root: str) -> str:
    return os.path.join(root, STATE_DIR, "results.json")


def _tree_fingerprint(root: str) -> Optional[str]:
    """HEAD sha plus whether the working tree is dirty; cached results are only reused on a match."""
    if not gitutil.has_commits(root):
        return None
    head = gitutil.rev_parse(root, "HEAD")
    dirty = gitutil.git(["status", "--porcelain", "--untracked-files=no"], cwd=root, check=False).strip()
    return head + ("+dirty" if dirty else "")


def save_cache(root: str, results: Dict[str, CheckResult]) -> None:
    fingerprint = _tree_fingerprint(root)
    if fingerprint is None or fingerprint.endswith("+dirty"):
        return
    path = _cache_path(root)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        existing = {}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                existing = json.load(fh)
        if existing.get("fingerprint") != fingerprint:
            existing = {"fingerprint": fingerprint, "results": {}}
        for name, res in results.items():
            existing["results"][name] = res.outcome
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(existing, fh, indent=2)
    except (OSError, ValueError):
        pass


def load_cache(root: str) -> Dict[str, str]:
    path = _cache_path(root)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    if data.get("fingerprint") != _tree_fingerprint(root):
        return {}
    return dict(data.get("results") or {})
