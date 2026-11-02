"""Thin wrappers over the git CLI.

A *source* names where file contents come from:
  - a commit-ish string (``"origin/main"``, a sha)
  - ``INDEX`` for the staging area
  - ``WORKTREE`` for files on disk
"""

from __future__ import annotations

import os
import subprocess
from typing import List, Optional

INDEX = ":index:"
WORKTREE = ":worktree:"


class GitError(RuntimeError):
    pass


def git(args: List[str], cwd: str, check: bool = True, input_text: Optional[str] = None) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check and proc.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def repo_root(cwd: str) -> Optional[str]:
    try:
        out = git(["rev-parse", "--show-toplevel"], cwd=cwd).strip()
    except (GitError, FileNotFoundError, NotADirectoryError):
        return None
    return out or None


def rev_exists(root: str, rev: str) -> bool:
    proc = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", rev + "^{commit}"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc.returncode == 0


def rev_parse(root: str, rev: str) -> str:
    return git(["rev-parse", rev], cwd=root).strip()


def merge_base(root: str, a: str, b: str) -> Optional[str]:
    out = git(["merge-base", a, b], cwd=root, check=False).strip()
    return out or None


def current_branch(root: str) -> Optional[str]:
    out = git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=root, check=False).strip()
    return None if out in ("", "HEAD") else out


def has_commits(root: str) -> bool:
    return rev_exists(root, "HEAD")


def resolve_base(root: str, base_branch: str, explicit: Optional[str] = None) -> Optional[str]:
    """Pick the ref that represents 'main' for diffing. Prefer the remote-tracking branch."""
    candidates = [explicit] if explicit else [f"origin/{base_branch}", base_branch]
    for cand in candidates:
        if cand and rev_exists(root, cand):
            return cand
    return None


def list_files(root: str, source: str) -> List[str]:
    if source == WORKTREE:
        out = git(["ls-files", "--cached", "--others", "--exclude-standard"], cwd=root)
        return [p for p in out.splitlines() if p and os.path.exists(os.path.join(root, p))]
    if source == INDEX:
        out = git(["ls-files", "--cached"], cwd=root)
        return [p for p in out.splitlines() if p]
    out = git(["ls-tree", "-r", "--name-only", source], cwd=root)
    return [p for p in out.splitlines() if p]


def read_file(root: str, source: str, path: str) -> Optional[str]:
    if source == WORKTREE:
        full = os.path.join(root, path)
        if not os.path.isfile(full):
            return None
        with open(full, encoding="utf-8") as fh:
            return fh.read()
    spec = f":{path}" if source == INDEX else f"{source}:{path}"
    proc = subprocess.run(
        ["git", "show", spec], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", errors="replace")


def changed_files(root: str, base: str, head: str) -> List[str]:
    """Files that differ between ``base`` (a commit) and ``head`` (commit, INDEX or WORKTREE)."""
    if head == INDEX:
        out = git(["diff", "--cached", "--name-only", "--no-renames", base], cwd=root)
        files = out.splitlines()
    elif head == WORKTREE:
        out = git(["diff", "--name-only", "--no-renames", base], cwd=root)
        files = out.splitlines()
        files += git(["ls-files", "--others", "--exclude-standard"], cwd=root).splitlines()
    else:
        out = git(["diff", "--name-only", "--no-renames", base, head], cwd=root)
        files = out.splitlines()
    return sorted({f for f in files if f})


def commit_messages(root: str, base: str, head: str) -> List[str]:
    """Commit messages reachable from ``head`` but not ``base``. INDEX/WORKTREE mean HEAD."""
    tip = "HEAD" if head in (INDEX, WORKTREE) else head
    if not rev_exists(root, tip):
        return []
    out = git(["log", "--format=%B%x00", f"{base}..{tip}"], cwd=root, check=False)
    return [m.strip() for m in out.split("\x00") if m.strip()]
