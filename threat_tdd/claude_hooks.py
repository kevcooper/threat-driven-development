"""Claude Code hook handlers. Each reads the hook JSON payload on stdin.

  session-start  injects threat model status and the TDD workflow as context
  post-tool-use  validates a .tc.json right after the agent edits it and puts it in
                 Threat Composer's canonical form so the VS Code editor won't rewrite it
  stop           refuses to end the turn when the session changed code but the
                 branch carries neither a threat delta nor a declaration

All handlers are silent no-ops in repositories without .tdd/config.json, so the
plugin can be installed globally and only acts where a repo has opted in.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Any, Dict, Optional, Tuple

from threat_tdd import checks as checks_mod
from threat_tdd import config as config_mod
from threat_tdd import gate as gate_mod
from threat_tdd import canonical, gitutil, globs, status
from threat_tdd.config import STATE_DIR
from threat_tdd.model import load_all, parse, validate

TDD_BIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "tdd")


def _emit(obj: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj))
    sys.stdout.write("\n")


def _context(payload: Dict[str, Any]) -> Optional[Tuple[str, config_mod.Config]]:
    if os.environ.get("TDD_DISABLE"):
        return None
    cwd = payload.get("cwd") or os.getcwd()
    root = gitutil.repo_root(cwd)
    if not root or not config_mod.is_initialized(root):
        return None
    try:
        cfg = config_mod.load(root)
    except ValueError:
        return None
    return (root, cfg) if cfg else None


def _fingerprint(root: str) -> str:
    h = hashlib.sha256()
    if gitutil.has_commits(root):
        h.update(gitutil.rev_parse(root, "HEAD").encode())
        h.update(gitutil.git(["diff", "HEAD", "--", ".", f":(exclude){STATE_DIR}"], cwd=root, check=False).encode())
    for path in gitutil.git(["ls-files", "--others", "--exclude-standard"], cwd=root, check=False).splitlines():
        full = os.path.join(root, path)
        try:
            st = os.stat(full)
            h.update(f"{path}:{st.st_size}:{st.st_mtime_ns}".encode())
        except OSError:
            pass
    return h.hexdigest()


def _snapshot_path(root: str, session_id: str) -> str:
    safe = "".join(c for c in session_id if c.isalnum() or c in "-_") or "default"
    return os.path.join(root, STATE_DIR, f"session-{safe}.json")


def _ensure_state_ignored(root: str) -> None:
    path = os.path.join(root, ".tdd", ".gitignore")
    if not os.path.exists(path):
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("state/\n")
        except OSError:
            pass


def session_start(payload: Dict[str, Any]) -> int:
    ctx = _context(payload)
    if not ctx:
        return 0
    root, cfg = ctx
    _ensure_state_ignored(root)
    session_id = str(payload.get("session_id") or "default")
    try:
        os.makedirs(os.path.join(root, STATE_DIR), exist_ok=True)
        with open(_snapshot_path(root, session_id), "w", encoding="utf-8") as fh:
            json.dump({"fingerprint": _fingerprint(root)}, fh)
    except OSError:
        pass

    loaded = load_all(root, gitutil.WORKTREE, cfg.models)
    states = status.evaluate(loaded.models, checks_mod.load_cache(root), cfg.checks.keys())
    base = gate_mod.default_base(root, cfg)
    result = gate_mod.run(root, cfg, base, gitutil.WORKTREE)

    lines = [
        "Threat Driven Development is active in this repository.",
        f"Threat model: {len(loaded.models)} file(s) matching {', '.join(cfg.models)}; "
        f"{status.summary(states)}.",
        f"Merge gate for this branch vs {cfg['base_branch']}: {'PASS' if result.passed else 'FAIL'} ({result.reason}).",
        "Rule: every change that reaches main carries a threat model delta (.tc.json, AWS Threat Composer format) "
        "or a justified no-threat-delta declaration. Work threat-first: when a change adds an input, output, "
        "dependency, data store, permission or trust boundary, add the threat statement (red), then the mitigation, "
        "then a check that proves it (green). A threat is resolved only with an explicit risk strategy tag "
        "(risk:mitigate, risk:accept, risk:transfer or risk:avoid); `tdd sync` moves statuses along with the work.",
        f"CLI: {TDD_BIN} (status | gate | add-threat | add-mitigation | link | declare | check). "
        "Use the threat-driven-development skill for the details.",
    ]
    red = [s for s in states if s.state == status.RED][:5]
    if red:
        lines.append("Red threats: " + "; ".join(f"{s.label} ({s.reason})" for s in red))
    _emit({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": "\n".join(lines)}})
    return 0


def post_tool_use(payload: Dict[str, Any]) -> int:
    ctx = _context(payload)
    if not ctx:
        return 0
    root, cfg = ctx
    tool_input = payload.get("tool_input") or {}
    file_path = tool_input.get("file_path") or tool_input.get("notebook_path")
    if not file_path:
        return 0
    full = os.path.abspath(os.path.join(payload.get("cwd") or root, file_path))
    rel = os.path.relpath(full, root).replace(os.sep, "/")
    if rel.startswith(".."):
        return 0

    if rel == config_mod.CONFIG_PATH:
        try:
            config_mod.load(root)
        except ValueError as exc:
            _emit({"decision": "block", "reason": f"{config_mod.CONFIG_PATH} is invalid: {exc}"})
        return 0
    if not globs.match_any(rel, cfg.models):
        return 0

    try:
        with open(full, encoding="utf-8", newline="") as fh:
            text = fh.read()
    except OSError:
        return 0
    res = canonical.format_text(text)
    r = res.report
    problems = [f"Threat Composer would refuse to open this file: {e}" for e in r.errors]
    if res.text is not None:
        try:
            model = parse(rel, res.text)
            problems += [i.message for i in validate(model, cfg.checks.keys()) if i.level == "error"]
        except ValueError as exc:
            problems.append(str(exc))
    if problems:
        _emit({
            "decision": "block",
            "reason": f"The threat model file you just edited ({rel}) is invalid. Fix it before continuing:\n"
            + "\n".join(f"- {p}" for p in problems),
        })
        return 0
    if r.changes or r.uncertain:
        _emit({
            "decision": "block",
            "reason": f"{rel} contains text that Threat Composer rewrites when the file is opened "
            "(it strips <tags> and escapes &, < and >). Rephrase these values without those characters, "
            "e.g. 'and' instead of '&' and a plain word instead of '<placeholder>':\n"
            + "\n".join(f"- {c}" for c in r.changes + r.uncertain),
        })
        return 0
    if res.changed:
        with open(full, "w", encoding="utf-8", newline="") as fh:
            fh.write(res.text)
        _emit({"hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": f"tdd reformatted {rel} into Threat Composer's canonical form (key order, "
            "list order, 2-space JSON, no trailing newline) so opening it in the VS Code extension won't "
            "rewrite it. Re-read the file before editing it again.",
        }})
    return 0


def stop(payload: Dict[str, Any]) -> int:
    if payload.get("stop_hook_active"):
        return 0  # we already blocked once this turn; don't loop
    ctx = _context(payload)
    if not ctx:
        return 0
    root, cfg = ctx
    mode = cfg.hook_mode("claude_stop")
    if mode == "off":
        return 0

    session_id = str(payload.get("session_id") or "default")
    snap = _snapshot_path(root, session_id)
    if os.path.exists(snap):
        try:
            with open(snap, encoding="utf-8") as fh:
                if json.load(fh).get("fingerprint") == _fingerprint(root):
                    return 0  # this session has not changed anything
        except (OSError, ValueError):
            pass

    result = gate_mod.run(root, cfg, gate_mod.default_base(root, cfg), gitutil.WORKTREE)
    if result.passed:
        return 0
    message = (
        "Threat Driven Development gate is failing for this branch.\n"
        + gate_mod.render(result)
        + "\n\nBefore finishing: review what the change does to attack surface. If it introduces or changes "
        "threats, add them to the threat model with mitigations and checks. If it truly does not, run "
        f"`{TDD_BIN} declare \"<specific reason>\"`. Do not write a vague declaration to get past this check."
    )
    if mode == "block":
        _emit({"decision": "block", "reason": message})
    else:
        _emit({"systemMessage": message})
    return 0


HANDLERS = {"session-start": session_start, "post-tool-use": post_tool_use, "stop": stop}


def main(event: str) -> int:
    handler = HANDLERS.get(event)
    if handler is None:
        sys.stderr.write(f"unknown hook event {event}\n")
        return 0
    raw = sys.stdin.read() if not sys.stdin.isatty() else ""
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        payload = {}
    try:
        return handler(payload)
    except Exception as exc:  # a broken hook must never wedge the agent
        sys.stderr.write(f"tdd {event} hook error: {exc}\n")
        return 0
