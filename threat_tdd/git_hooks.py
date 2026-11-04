"""Portable git hooks: commit-msg (advisory by default), pre-push (blocking by default)
and post-commit (tags commits that resolve mitigations).

They are deliberately thin: each one shells out to ``tdd git-hook <name>`` so the
same logic runs in hooks, in Claude Code, and in CI. ``git commit --no-verify``
and ``git push --no-verify`` still work; CI is the backstop that cannot be skipped.
"""

from __future__ import annotations

import os
import stat
import sys
from typing import List, Optional

from threat_tdd import config as config_mod
from threat_tdd import gate as gate_mod
from threat_tdd import gitutil

MARKER = "# installed by tdd (threat driven development)"
HOOKS = ("commit-msg", "pre-push", "post-commit")
ZERO = "0" * 40

TEMPLATE = """#!/bin/sh
{marker}
# Override the CLI with TDD_BIN=/path/to/tdd. Skip once with --no-verify.
hook_dir=$(cd "$(dirname "$0")" && pwd)
if [ -x "$hook_dir/{name}.pre-tdd" ]; then
  "$hook_dir/{name}.pre-tdd" "$@" || exit $?
fi
TDD="${{TDD_BIN:-}}"
if [ -z "$TDD" ] && [ -n "{recorded}" ] && [ -x "{recorded}" ]; then TDD="{recorded}"; fi
if [ -z "$TDD" ] && command -v tdd >/dev/null 2>&1; then TDD=tdd; fi
if [ -z "$TDD" ]; then
  if python3 -c "import threat_tdd" >/dev/null 2>&1; then
    exec python3 -m threat_tdd git-hook {name} "$@"
  fi
  echo "tdd: CLI not found, skipping the threat gate (CI still enforces it)" >&2
  exit 0
fi
exec "$TDD" git-hook {name} "$@"
"""


def hooks_dir(root: str) -> str:
    path = gitutil.git(["rev-parse", "--git-path", "hooks"], cwd=root).strip()
    return path if os.path.isabs(path) else os.path.join(root, path)


def install(root: str, shared: bool = False, force: bool = False) -> List[str]:
    """Install hooks. ``shared`` writes them to .githooks/ (commit it) and points core.hooksPath there."""
    recorded = "" if shared else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "tdd"
    )
    if shared:
        target = os.path.join(root, ".githooks")
        os.makedirs(target, exist_ok=True)
        gitutil.git(["config", "core.hooksPath", ".githooks"], cwd=root)
    else:
        target = hooks_dir(root)
        os.makedirs(target, exist_ok=True)
    written = []
    for name in HOOKS:
        path = os.path.join(target, name)
        if os.path.exists(path):
            with open(path, encoding="utf-8", errors="replace") as fh:
                existing = fh.read()
            if MARKER not in existing:
                backup = path + ".pre-tdd"
                if os.path.exists(backup) and not force:
                    raise FileExistsError(f"{path} exists and {backup} already taken; use --force")
                os.replace(path, backup)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(TEMPLATE.format(marker=MARKER, name=name, recorded=recorded))
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        written.append(os.path.relpath(path, root))
    # Annotated mitigation tags travel with an ordinary `git push`.
    gitutil.git(["config", "push.followTags", "true"], cwd=root)
    return written


def uninstall(root: str) -> List[str]:
    removed = []
    candidates = [hooks_dir(root), os.path.join(root, ".githooks")]
    for directory in candidates:
        for name in HOOKS:
            path = os.path.join(directory, name)
            if not os.path.exists(path):
                continue
            with open(path, encoding="utf-8", errors="replace") as fh:
                if MARKER not in fh.read():
                    continue
            os.remove(path)
            removed.append(os.path.relpath(path, root))
            if os.path.exists(path + ".pre-tdd"):
                os.replace(path + ".pre-tdd", path)
    return removed


def _strip_comments(message: str) -> str:
    return "\n".join(l for l in message.splitlines() if not l.startswith("#"))


def commit_msg(root: str, args: List[str]) -> int:
    cfg = config_mod.load(root)
    if cfg is None:
        return 0
    mode = cfg.hook_mode("commit_msg")
    if mode == "off":
        return 0
    git_dir = gitutil.git(["rev-parse", "--git-dir"], cwd=root).strip()
    git_dir = git_dir if os.path.isabs(git_dir) else os.path.join(root, git_dir)
    if os.path.exists(os.path.join(git_dir, "MERGE_HEAD")):
        return 0
    message = ""
    if args:
        try:
            with open(args[0], encoding="utf-8") as fh:
                message = _strip_comments(fh.read())
        except OSError:
            pass
    base = "HEAD" if gitutil.has_commits(root) else None
    result = gate_mod.run(root, cfg, base, gitutil.INDEX, extra_messages=[message])
    if result.passed:
        return 0
    sys.stderr.write("tdd: this commit changes code without a threat model delta or declaration.\n")
    sys.stderr.write(gate_mod.render(result) + "\n")
    if mode == "block":
        sys.stderr.write("\nCommit blocked (hooks.commit_msg = block). Use --no-verify to bypass.\n")
        return 1
    sys.stderr.write("\n(advisory: the pre-push hook and CI enforce this across the whole branch)\n")
    return 0


def _pre_commit_framework_line() -> Optional[str]:
    """The pre-commit framework passes push details in env vars instead of stdin."""
    to_ref = os.environ.get("PRE_COMMIT_TO_REF")
    if not to_ref:
        return None
    local = os.environ.get("PRE_COMMIT_LOCAL_BRANCH", "HEAD")
    remote = os.environ.get("PRE_COMMIT_REMOTE_BRANCH", "refs/heads/unknown")
    from_ref = os.environ.get("PRE_COMMIT_FROM_REF") or ZERO
    return f"{local} {to_ref} {remote} {from_ref}\n"


def pre_push(root: str, args: List[str], stdin_text: Optional[str] = None) -> int:
    cfg = config_mod.load(root)
    if cfg is None:
        return 0
    mode = cfg.hook_mode("pre_push")
    if mode == "off":
        return 0
    if stdin_text is None:
        stdin_text = _pre_commit_framework_line() or ("" if sys.stdin.isatty() else sys.stdin.read())
    text = stdin_text
    base_ref = gitutil.resolve_base(root, cfg["base_branch"])
    failed = False
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 4:
            continue
        local_ref, local_sha, remote_ref, remote_sha = parts
        if local_sha == ZERO:
            continue  # branch deletion
        if remote_ref == f"refs/heads/{cfg['base_branch']}" and remote_sha != ZERO:
            base = remote_sha if gitutil.rev_exists(root, remote_sha) else base_ref
        else:
            base = base_ref
        if base is None:
            continue
        mb = gitutil.merge_base(root, base, local_sha)
        if mb == gitutil.rev_parse(root, local_sha):
            continue  # nothing new relative to base
        result = gate_mod.run(root, cfg, base, local_sha)
        if not result.passed:
            failed = True
            sys.stderr.write(f"tdd: {local_ref} -> {remote_ref}\n{gate_mod.render(result)}\n")
    if failed and mode == "block":
        sys.stderr.write("\nPush blocked by the threat gate (hooks.pre_push = block). Use --no-verify to bypass.\n")
        return 1
    return 0


def post_commit(root: str, args: List[str]) -> int:
    """Tag the commit just made if it resolved any mitigations. Never fails the commit."""
    from threat_tdd import tagging

    cfg = config_mod.load(root)
    if cfg is None or not tagging.tags_enabled(cfg):
        return 0
    git_dir = gitutil.git(["rev-parse", "--git-dir"], cwd=root).strip()
    git_dir = git_dir if os.path.isabs(git_dir) else os.path.join(root, git_dir)
    if any(os.path.exists(os.path.join(git_dir, d)) for d in ("rebase-merge", "rebase-apply")):
        return 0  # tags are settled once the rewrite finishes (tdd tag)
    for r in tagging.resolved_in(root, cfg, "HEAD"):
        r = tagging.apply(root, cfg, tagging.plan(root, cfg, r))
        if r.action in ("created", "moved"):
            sys.stderr.write(f"tdd: {r.action} tag {r.tag} ({r.label} resolved in this commit)\n")
        elif r.action == "skipped":
            sys.stderr.write(f"tdd: not tagging {r.label}: {r.reason}\n")
    return 0


def main(name: str, args: List[str]) -> int:
    root = gitutil.repo_root(os.getcwd())
    if not root or os.environ.get("TDD_DISABLE"):
        return 0
    try:
        if name == "commit-msg":
            return commit_msg(root, args)
        if name == "pre-push":
            return pre_push(root, args)
        if name == "post-commit":
            return post_commit(root, args)
    except (gitutil.GitError, ValueError) as exc:
        sys.stderr.write(f"tdd {name}: {exc}\n")
        return 0
    sys.stderr.write(f"tdd: unknown git hook {name}\n")
    return 0
