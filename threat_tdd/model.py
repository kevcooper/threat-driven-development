"""Reading, validating and editing AWS Threat Composer ``.tc.json`` files.

Only the parts of the format that TDD relies on are interpreted; every other
field is preserved untouched when a file is rewritten.

TDD conventions layered on top of Threat Composer:
  - A mitigation is linked to a threat with a normal ``mitigationLinks`` entry.
  - A mitigation is linked to a *check* with a tag ``check:<name>``, where
    ``<name>`` is a key in ``.tdd/config.json`` -> ``checks``. Tags are
    editable in the Threat Composer UI, so humans can maintain the link too.
  - A threat is waived (accepted risk) by setting status
    ``threatResolvedNotUseful`` and explaining why in its ``Comments`` metadata.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from threat_tdd import globs, gitutil

CHECK_TAG_PREFIX = "check:"

THREAT_STATUSES = {"threatIdentified", "threatResolved", "threatResolvedNotUseful"}
MITIGATION_STATUSES = {
    "mitigationIdentified",
    "mitigationInProgress",
    "mitigationResolved",
    "mitigationResolvedWillNotAction",
}
WAIVED = "threatResolvedNotUseful"
WONT_DO = "mitigationResolvedWillNotAction"

STRIDE = {"S", "T", "R", "I", "D", "E"}


def empty_model(name: str = "", description: str = "") -> Dict[str, Any]:
    return {
        "schema": 1,
        "applicationInfo": {"name": name, "description": description},
        "architecture": {"description": ""},
        "dataflow": {"description": ""},
        "assumptions": [],
        "mitigations": [],
        "assumptionLinks": [],
        "mitigationLinks": [],
        "threats": [],
    }


def compose_statement(
    source: str,
    prerequisites: str,
    action: str,
    impact: str,
    goals: Iterable[str] = (),
    assets: Iterable[str] = (),
) -> str:
    """Threat Composer's threat grammar."""
    source = source.strip()
    article = "An" if source[:1].lower() in "aeiou" else "A"
    parts = [f"{article} {source}"]
    if prerequisites.strip():
        parts.append(prerequisites.strip())
    text = " ".join(parts) + f" can {action.strip()}"
    if impact.strip():
        text += f", which leads to {impact.strip()}"
    goals = [g.strip() for g in goals if g.strip()]
    assets = [a.strip() for a in assets if a.strip()]
    if goals or assets:
        text += ", resulting in reduced " + _join(goals or ["security"])
        if assets:
            text += " of " + _join(assets)
    return text


def _join(items: List[str]) -> str:
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def metadata_value(item: Dict[str, Any], key: str) -> Any:
    for entry in item.get("metadata") or []:
        if isinstance(entry, dict) and entry.get("key") == key:
            return entry.get("value")
    return None


def set_metadata(item: Dict[str, Any], key: str, value: Any) -> None:
    meta = item.setdefault("metadata", [])
    for entry in meta:
        if isinstance(entry, dict) and entry.get("key") == key:
            entry["value"] = value
            return
    meta.append({"key": key, "value": value})


def check_names(mitigation: Dict[str, Any]) -> List[str]:
    names = []
    for tag in mitigation.get("tags") or []:
        if isinstance(tag, str) and tag.startswith(CHECK_TAG_PREFIX):
            name = tag[len(CHECK_TAG_PREFIX):].strip()
            if name:
                names.append(name)
    return names


def threat_label(threat: Dict[str, Any]) -> str:
    num = threat.get("numericId")
    return f"T-{num}" if num is not None else str(threat.get("id", "?"))[:8]


def mitigation_label(mitigation: Dict[str, Any]) -> str:
    num = mitigation.get("numericId")
    return f"M-{num}" if num is not None else str(mitigation.get("id", "?"))[:8]


@dataclass
class Model:
    path: str
    data: Dict[str, Any]

    @property
    def threats(self) -> List[Dict[str, Any]]:
        return [t for t in self.data.get("threats") or [] if isinstance(t, dict)]

    @property
    def mitigations(self) -> List[Dict[str, Any]]:
        return [m for m in self.data.get("mitigations") or [] if isinstance(m, dict)]

    @property
    def assumptions(self) -> List[Dict[str, Any]]:
        return [a for a in self.data.get("assumptions") or [] if isinstance(a, dict)]

    @property
    def mitigation_links(self) -> List[Dict[str, Any]]:
        return [l for l in self.data.get("mitigationLinks") or [] if isinstance(l, dict)]

    @property
    def assumption_links(self) -> List[Dict[str, Any]]:
        return [l for l in self.data.get("assumptionLinks") or [] if isinstance(l, dict)]

    def mitigations_for(self, threat_id: str) -> List[Dict[str, Any]]:
        ids = {l.get("mitigationId") for l in self.mitigation_links if l.get("linkedId") == threat_id}
        return [m for m in self.mitigations if m.get("id") in ids]

    # ---- lookup -----------------------------------------------------------------

    def find_threat(self, ref: str) -> Dict[str, Any]:
        return _find(self.threats, ref, "T", "threat")

    def find_mitigation(self, ref: str) -> Dict[str, Any]:
        return _find(self.mitigations, ref, "M", "mitigation")

    # ---- editing ----------------------------------------------------------------

    def _next_numeric(self, key: str) -> int:
        nums = [x.get("numericId") for x in self.data.get(key) or [] if isinstance(x, dict)]
        nums = [n for n in nums if isinstance(n, int)]
        return (max(nums) + 1) if nums else 1

    def add_threat(
        self,
        source: str,
        prerequisites: str,
        action: str,
        impact: str,
        goals: List[str],
        assets: List[str],
        stride: Optional[List[str]] = None,
        priority: Optional[str] = None,
        comments: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        num = self._next_numeric("threats")
        threat: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "numericId": num,
            "displayOrder": num,
            "statement": compose_statement(source, prerequisites, action, impact, goals, assets),
            "threatSource": source,
            "prerequisites": prerequisites,
            "threatAction": action,
            "threatImpact": impact,
            "impactedGoal": goals,
            "impactedAssets": assets,
            "metadata": [],
            "tags": list(tags or []),
            "status": "threatIdentified",
        }
        if stride:
            set_metadata(threat, "STRIDE", [s.upper() for s in stride])
        if priority:
            set_metadata(threat, "Priority", priority.capitalize())
        if comments:
            set_metadata(threat, "Comments", comments)
        self.data.setdefault("threats", []).append(threat)
        return threat

    def add_mitigation(
        self, content: str, checks: Optional[List[str]] = None, comments: Optional[str] = None
    ) -> Dict[str, Any]:
        num = self._next_numeric("mitigations")
        mitigation: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "numericId": num,
            "displayOrder": num,
            "content": content,
            "metadata": [],
            "tags": [CHECK_TAG_PREFIX + c for c in checks or []],
            "status": "mitigationIdentified",
        }
        if comments:
            set_metadata(mitigation, "Comments", comments)
        self.data.setdefault("mitigations", []).append(mitigation)
        return mitigation

    def link(self, mitigation_id: str, threat_id: str) -> bool:
        for l in self.mitigation_links:
            if l.get("mitigationId") == mitigation_id and l.get("linkedId") == threat_id:
                return False
        self.data.setdefault("mitigationLinks", []).append(
            {"mitigationId": mitigation_id, "linkedId": threat_id}
        )
        return True

    def add_check_tag(self, mitigation: Dict[str, Any], check: str) -> None:
        tag = CHECK_TAG_PREFIX + check
        tags = mitigation.setdefault("tags", [])
        if tag not in tags:
            tags.append(tag)

    def waive(self, threat: Dict[str, Any], reason: str) -> None:
        threat["status"] = WAIVED
        existing = metadata_value(threat, "Comments")
        note = f"Accepted risk: {reason.strip()}"
        set_metadata(threat, "Comments", f"{existing}\n\n{note}".strip() if existing else note)

    def save(self, root: str) -> None:
        full = os.path.join(root, self.path)
        os.makedirs(os.path.dirname(full) or ".", exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")


def _find(items: List[Dict[str, Any]], ref: str, prefix: str, kind: str) -> Dict[str, Any]:
    ref = ref.strip()
    numeric = ref
    if ref.upper().startswith(prefix + "-"):
        numeric = ref[len(prefix) + 1:]
    if numeric.isdigit():
        for item in items:
            if item.get("numericId") == int(numeric):
                return item
    matches = [i for i in items if str(i.get("id", "")).startswith(ref)] if ref else []
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise KeyError(f"{kind} reference '{ref}' is ambiguous")
    raise KeyError(f"no {kind} matches '{ref}'")


# ---- loading ------------------------------------------------------------------


@dataclass
class LoadResult:
    models: List[Model] = field(default_factory=list)
    errors: List[Tuple[str, str]] = field(default_factory=list)  # (path, message)


def model_paths(root: str, source: str, patterns: List[str]) -> List[str]:
    return sorted(p for p in gitutil.list_files(root, source) if globs.match_any(p, patterns))


def parse(path: str, text: str) -> Model:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("top level must be a JSON object")
    return Model(path, data)


def load_all(root: str, source: str, patterns: List[str]) -> LoadResult:
    result = LoadResult()
    for path in model_paths(root, source, patterns):
        text = gitutil.read_file(root, source, path)
        if text is None:
            continue
        try:
            result.models.append(parse(path, text))
        except (ValueError, json.JSONDecodeError) as exc:
            result.errors.append((path, f"cannot parse: {exc}"))
    return result


def load_file(root: str, path: str) -> Model:
    full = os.path.join(root, path)
    if not os.path.exists(full):
        raise FileNotFoundError(path)
    with open(full, encoding="utf-8") as fh:
        return parse(os.path.relpath(full, root).replace(os.sep, "/"), fh.read())


# ---- validation ---------------------------------------------------------------


@dataclass
class Issue:
    path: str
    level: str  # "error" | "warning"
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.level}: {self.message}"


def validate(model: Model, known_checks: Optional[Iterable[str]] = None) -> List[Issue]:
    issues: List[Issue] = []

    def err(msg: str) -> None:
        issues.append(Issue(model.path, "error", msg))

    def warn(msg: str) -> None:
        issues.append(Issue(model.path, "warning", msg))

    data = model.data
    for key in ("threats", "mitigations", "assumptions", "mitigationLinks", "assumptionLinks"):
        if key in data and not isinstance(data[key], list):
            err(f"'{key}' must be an array")
    if issues:
        return issues

    def unique(items: List[Dict[str, Any]], kind: str) -> set:
        ids, nums = set(), set()
        for item in items:
            iid = item.get("id")
            if not isinstance(iid, str) or not iid:
                err(f"{kind} without an id: {json.dumps(item)[:80]}")
                continue
            if iid in ids:
                err(f"duplicate {kind} id {iid}")
            ids.add(iid)
            num = item.get("numericId")
            if num is not None:
                if num in nums:
                    err(f"duplicate {kind} numericId {num}")
                nums.add(num)
        return ids

    threat_ids = unique(model.threats, "threat")
    mitigation_ids = unique(model.mitigations, "mitigation")
    assumption_ids = unique(model.assumptions, "assumption")

    for t in model.threats:
        label = threat_label(t)
        if not str(t.get("statement") or "").strip() and not str(t.get("threatAction") or "").strip():
            err(f"{label} has no statement")
        status = t.get("status")
        if status is not None and status not in THREAT_STATUSES:
            err(f"{label} has unknown status '{status}'")
        if status == WAIVED and not str(metadata_value(t, "Comments") or "").strip():
            err(f"{label} is marked not-useful (waived) but has no Comments explaining why")
        stride = metadata_value(t, "STRIDE")
        if stride is not None:
            bad = [s for s in (stride if isinstance(stride, list) else [stride]) if s not in STRIDE]
            if bad:
                err(f"{label} has invalid STRIDE values {bad}")

    known = set(known_checks) if known_checks is not None else None
    for m in model.mitigations:
        label = mitigation_label(m)
        if not str(m.get("content") or "").strip():
            err(f"{label} has no content")
        status = m.get("status")
        if status is not None and status not in MITIGATION_STATUSES:
            err(f"{label} has unknown status '{status}'")
        if known is not None:
            for name in check_names(m):
                if name not in known:
                    warn(f"{label} references check '{name}' which is not defined in .tdd/config.json")

    for l in model.mitigation_links:
        if l.get("mitigationId") not in mitigation_ids:
            err(f"mitigationLink references unknown mitigation {l.get('mitigationId')}")
        if l.get("linkedId") not in threat_ids:
            err(f"mitigationLink references unknown threat {l.get('linkedId')}")
    for l in model.assumption_links:
        if l.get("assumptionId") not in assumption_ids:
            err(f"assumptionLink references unknown assumption {l.get('assumptionId')}")
        if l.get("linkedId") not in threat_ids | mitigation_ids:
            err(f"assumptionLink references unknown item {l.get('linkedId')}")
    return issues
