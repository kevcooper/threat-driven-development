"""Semantic difference between two versions of the threat model.

Formatting, key order, ``displayOrder`` and ``numericId`` churn are not deltas.
Only threats, mitigations, assumptions and the links between them count.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from threat_tdd import gitutil
from threat_tdd.model import Model, load_all, mitigation_label, threat_label

IGNORED_FIELDS = {"displayOrder", "numericId"}


@dataclass
class Change:
    kind: str  # threat | mitigation | assumption | mitigationLink | assumptionLink
    op: str  # added | removed | changed
    path: str
    id: str
    label: str
    detail: str = ""

    def as_dict(self) -> Dict[str, str]:
        return self.__dict__.copy()

    def __str__(self) -> str:
        text = f"{self.op:7} {self.kind} {self.label}"
        return text + (f": {self.detail}" if self.detail else "")


@dataclass
class Delta:
    changes: List[Change] = field(default_factory=list)
    errors: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not self.changes

    def added_threat_keys(self) -> set:
        return {(c.path, c.id) for c in self.changes if c.kind == "threat" and c.op == "added"}


def _normalize(item: Dict[str, Any]) -> str:
    return json.dumps({k: v for k, v in item.items() if k not in IGNORED_FIELDS}, sort_keys=True)


def _short(text: Any, limit: int = 90) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def diff_models(path: str, old: Optional[Model], new: Optional[Model]) -> List[Change]:
    changes: List[Change] = []
    specs = [
        ("threat", "threats", threat_label, "statement"),
        ("mitigation", "mitigations", mitigation_label, "content"),
        ("assumption", "assumptions", lambda a: f"A-{a.get('numericId', '?')}", "content"),
    ]
    for kind, key, labeler, text_field in specs:
        before = {i["id"]: i for i in (old.data.get(key) if old else []) or [] if isinstance(i, dict) and "id" in i}
        after = {i["id"]: i for i in (new.data.get(key) if new else []) or [] if isinstance(i, dict) and "id" in i}
        for iid, item in after.items():
            if iid not in before:
                changes.append(Change(kind, "added", path, iid, labeler(item), _short(item.get(text_field))))
            elif _normalize(item) != _normalize(before[iid]):
                fields = sorted(
                    k
                    for k in set(item) | set(before[iid])
                    if k not in IGNORED_FIELDS and item.get(k) != before[iid].get(k)
                )
                changes.append(Change(kind, "changed", path, iid, labeler(item), ", ".join(fields)))
        for iid, item in before.items():
            if iid not in after:
                changes.append(Change(kind, "removed", path, iid, labeler(item), _short(item.get(text_field))))

    for kind, key, a, b in (
        ("mitigationLink", "mitigationLinks", "mitigationId", "linkedId"),
        ("assumptionLink", "assumptionLinks", "assumptionId", "linkedId"),
    ):
        def links(m: Optional[Model]) -> set:
            return {
                (l.get(a), l.get(b))
                for l in (m.data.get(key) if m else []) or []
                if isinstance(l, dict)
            }

        before_l, after_l = links(old), links(new)
        for x, y in sorted(after_l - before_l, key=str):
            changes.append(Change(kind, "added", path, f"{x}->{y}", f"{str(x)[:8]} -> {str(y)[:8]}"))
        for x, y in sorted(before_l - after_l, key=str):
            changes.append(Change(kind, "removed", path, f"{x}->{y}", f"{str(x)[:8]} -> {str(y)[:8]}"))
    return changes


def compute(root: str, base: str, head: str, patterns: List[str]) -> Delta:
    """Delta from ``base`` (commit) to ``head`` (commit, INDEX or WORKTREE)."""
    old = load_all(root, base, patterns)
    new = load_all(root, head, patterns)
    delta = Delta(errors=list(new.errors))
    old_by_path = {m.path: m for m in old.models}
    new_by_path = {m.path: m for m in new.models}
    for path in sorted(set(old_by_path) | set(new_by_path)):
        delta.changes.extend(diff_models(path, old_by_path.get(path), new_by_path.get(path)))
    return delta


def empty_source_delta(root: str, head: str, patterns: List[str]) -> Delta:
    """Delta for a repository with no base commit: everything at head is new."""
    new = load_all(root, head, patterns)
    delta = Delta(errors=list(new.errors))
    for m in new.models:
        delta.changes.extend(diff_models(m.path, None, m))
    return delta


__all__ = ["Change", "Delta", "compute", "diff_models", "empty_source_delta", "gitutil"]
