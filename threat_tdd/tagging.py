"""Git tags on the commits that resolve mitigations.

A mitigation is resolved in the same commit as the code that implements it
(``tdd sync`` flips its status), so that commit is where the mitigation landed.
``tdd`` marks it with an annotated tag named after the model and the mitigation's
friendly id, the ``M-<n>`` label shown in Threat Composer, under a ``tdd/``
namespace that keeps them apart from release tags::

    tdd/<model>/M-<n>    e.g. tdd/billing/M-3 for M-3 in threats/billing.tc.json

The model name is the model's file name without ``.tc.json``, made safe for a git
ref. The namespace is ``tags.prefix`` in ``.tdd/config.json`` (default ``tdd``; an
empty prefix gives ``<model>/M-<n>``).

The tag message records the mitigation, the threats it covers, its checks and its
priority, so ``git show tdd/billing/M-3`` answers "when and how was this mitigated?".

- A post-commit hook tags new commits (``tdd hooks install``).
- ``tdd tag`` tags any range, which is how CI tags ``main`` after squash merges.
- An amended or rebased commit moves the tag to the new commit, since it's the
  same event, rewritten.
- If a mitigation regresses and is resolved again later, the later commit gets
  ``tdd/<model>/M-<n>-r2``, ``-r3`` and so on.
- A name already used by a different mitigation (two model files with the same
  name in different folders) or by a tag tdd didn't create is left alone, and the
  resolution is skipped with a warning.

Tag names are built only from the slugged file name and the integer numericId, and
are checked with ``git check-ref-format``. Tag text goes to git on stdin, never on a
command line.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from threat_tdd import gitutil
from threat_tdd.config import Config
from threat_tdd.model import (
    Model,
    check_names,
    metadata_value,
    mitigation_label,
    parse,
    priority_tags,
    threat_label,
)

RESOLVED = "mitigationResolved"


@dataclass
class Resolution:
    commit: str
    model_path: str
    mitigation_id: str
    label: str  # M-3
    numeric_id: Any = None
    tag: str = ""
    action: str = ""  # created | moved | exists | would-create | would-move | skipped
    reason: str = ""  # why it was skipped

    def as_dict(self) -> Dict[str, str]:
        return self.__dict__.copy()


def tag_prefix(cfg: Config) -> str:
    return str((cfg.data.get("tags") or {}).get("prefix", "tdd")).strip().strip("/")


def tags_enabled(cfg: Config) -> bool:
    return bool((cfg.data.get("tags") or {}).get("mitigations", True))


def model_slug(path: str) -> str:
    """The model's name for tags: its file name without .tc.json, safe for a git ref."""
    name = os.path.basename(path)
    name = name[: -len(".tc.json")] if name.endswith(".tc.json") else os.path.splitext(name)[0]
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", name)
    name = re.sub(r"\.{2,}", ".", name).strip(".-")
    if name.endswith(".lock"):
        name = name[: -len(".lock")]
    return name or "model"


def base_tag(cfg: Config, model_path: str, numeric_id: Any) -> Optional[str]:
    """tdd/<model>/M-<n> (or <prefix>/<model>/M-<n>), None when numericId isn't whole."""
    if isinstance(numeric_id, bool) or not isinstance(numeric_id, (int, float)) or numeric_id != int(numeric_id):
        return None
    name = f"{model_slug(model_path)}/M-{int(numeric_id)}"
    prefix = tag_prefix(cfg)
    return f"{prefix}/{name}" if prefix else name


def _valid_ref(root: str, tag: str) -> bool:
    return subprocess.run(["git", "check-ref-format", f"refs/tags/{tag}"], cwd=root,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def _models_at(root: str, cfg: Config, rev: Optional[str]) -> Dict[str, Model]:
    if rev is None:
        return {}
    out = {}
    from threat_tdd.model import model_paths
    for path in model_paths(root, rev, cfg.models):
        text = gitutil.read_file(root, rev, path)
        if text is None:
            continue
        try:
            out[path] = parse(path, text)
        except (ValueError, json.JSONDecodeError):
            continue
    return out


def resolved_in(root: str, cfg: Config, commit: str) -> List[Resolution]:
    """Mitigations whose status became mitigationResolved in ``commit`` (vs its first parent)."""
    parent = _first_parent(root, commit)
    before = _models_at(root, cfg, parent)
    after = _models_at(root, cfg, commit)
    found = []
    for path, model in after.items():
        old = {m.get("id"): m for m in (before[path].mitigations if path in before else [])}
        for m in model.mitigations:
            if m.get("status") == RESOLVED and old.get(m.get("id"), {}).get("status") != RESOLVED:
                found.append(Resolution(commit, path, m["id"], mitigation_label(m), m.get("numericId")))
    return found


def tag_message(model: Model, mitigation: Dict) -> str:
    label = mitigation_label(mitigation)
    lines = [f"{label} resolved: {mitigation.get('content', '')}", "", f"Model: {model.path}"]
    for t in model.linked_threats(mitigation.get("id")):
        prio = metadata_value(t, "Priority")
        lines.append(f"Threat: {threat_label(t)}{f' ({prio})' if prio else ''}: {t.get('statement', '')}")
    checks = check_names(mitigation)
    if checks:
        lines.append(f"Checks: {', '.join(checks)}")
    prio = priority_tags(mitigation)
    if prio:
        lines.append(f"Priority: {prio[0].split(':', 1)[1]}")
    lines.append(f"Mitigation id: {mitigation.get('id')}")
    return "\n".join(lines) + "\n"


def _tag_target(root: str, tag: str) -> Optional[str]:
    out = gitutil.git(["rev-parse", "-q", "--verify", f"refs/tags/{tag}^{{commit}}"], cwd=root, check=False).strip()
    return out or None


def _tag_mitigation_id(root: str, tag: str) -> Optional[str]:
    body = gitutil.git(["tag", "-l", "--format=%(contents)", "--", tag], cwd=root, check=False)
    m = re.search(r"^Mitigation id: (\S+)$", body, re.MULTILINE)
    return m.group(1) if m else None


def _is_ancestor(root: str, a: str, b: str) -> bool:
    return subprocess.run(["git", "merge-base", "--is-ancestor", a, b], cwd=root,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def _first_parent(root: str, commit: str) -> Optional[str]:
    parents = gitutil.git(["rev-list", "--parents", "-n", "1", commit], cwd=root).split()[1:]
    return parents[0] if parents else None


def plan(root: str, cfg: Config, r: Resolution) -> Resolution:
    """Choose the tag name and action for a resolution.

    - no tag yet                                   -> create
    - tag already on this commit                   -> exists
    - tag for another mitigation, or not tdd's     -> skipped, with a reason
    - tag on an earlier mainline commit            -> resolved before, regressed,
                                                      resolved again: next suffix
    - tag on a commit merged in with this one      -> exists (the branch commit that
                                                      did the work keeps its tag)
    - tag on a commit not in this history          -> move (amend, rebase, squash)
    """
    base = base_tag(cfg, r.model_path, r.numeric_id)
    if base is None:
        r.action, r.reason = "skipped", f"numericId {r.numeric_id!r} isn't a whole number"
        return r
    parent = _first_parent(root, r.commit)
    n = 1
    while True:
        tag = base if n == 1 else f"{base}-r{n}"
        target = _tag_target(root, tag)
        if target is None:
            r.tag, r.action = tag, "create"
            return r
        recorded = _tag_mitigation_id(root, tag)
        if recorded != r.mitigation_id:
            r.tag, r.action = tag, "skipped"
            r.reason = (f"tag {tag} already marks a different mitigation ({recorded})" if recorded
                        else f"tag {tag} already exists and wasn't created by tdd")
            return r
        if target == r.commit:
            r.tag, r.action = tag, "exists"
            return r
        if _is_ancestor(root, target, r.commit):
            if parent is not None and _is_ancestor(root, target, parent):
                n += 1
                continue
            r.tag, r.action = tag, "exists"
            return r
        r.tag, r.action = tag, "move"
        return r


def apply(root: str, cfg: Config, r: Resolution, dry_run: bool = False) -> Resolution:
    if r.action == "skipped":
        return r
    if not _valid_ref(root, r.tag):
        r.action, r.reason = "skipped", f"{r.tag!r} isn't a valid git tag name"
        return r
    if r.action == "exists":
        return r
    if dry_run:
        r.action = "would-" + r.action
        return r
    model = _models_at(root, cfg, r.commit)[r.model_path]
    mitigation = model.find_mitigation(r.mitigation_id)
    args = ["tag", "-a"] + (["-f"] if r.action == "move" else []) + ["-F", "-", "--", r.tag, r.commit]
    gitutil.git(args, cwd=root, input_text=tag_message(model, mitigation))
    r.action = "created" if r.action == "create" else "moved"
    return r


def commits_between(root: str, base: Optional[str], head: str) -> List[str]:
    spec = [f"{base}..{head}"] if base else [head]
    out = gitutil.git(["rev-list", "--reverse", "--first-parent", *spec], cwd=root)
    return [c for c in out.split() if c]


def tag_range(root: str, cfg: Config, base: Optional[str], head: str, dry_run: bool = False) -> List[Resolution]:
    done = []
    for commit in commits_between(root, base, head):
        for r in resolved_in(root, cfg, commit):
            done.append(apply(root, cfg, plan(root, cfg, r), dry_run))
    return done


def push(root: str, resolutions: List[Resolution], remote: str = "origin") -> None:
    refs = []
    for r in resolutions:
        if r.action == "created":
            refs.append(f"refs/tags/{r.tag}")
        elif r.action == "moved":
            refs.append(f"+refs/tags/{r.tag}")
    if refs:
        gitutil.git(["push", remote, *refs], cwd=root)
