"""Reading, validating and editing AWS Threat Composer ``.tc.json`` files.

Files are always written in the exact form the Threat Composer editor writes
(see ``canonical.py``), so opening a file written by ``tdd`` in the AWS Toolkit
for VS Code does not dirty it.

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

from threat_tdd import canonical, globs, gitutil

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

STRIDE = set(canonical.STRIDE)
MAX_CHECK_NAME = canonical.TAG_MAX - len(CHECK_TAG_PREFIX)


def clean_text(label: str, value: str, max_len: Optional[int] = None) -> str:
    """Reject text Threat Composer would rewrite on load (tags stripped, &, <, > escaped)."""
    value = value.strip()
    try:
        stored = canonical.sanitize_string(value)
    except canonical.Uncertain:
        stored = None
    if stored != value:
        hint = f" (Threat Composer would store {stored!r})" if stored is not None else ""
        raise ValueError(
            f"{label} contains '<', '>' or '&', which Threat Composer strips or escapes{hint}; "
            "rephrase it, e.g. 'and' instead of '&', a word instead of '<placeholder>'"
        )
    if max_len is not None and canonical._u16len(value) > max_len:
        raise ValueError(f"{label} is longer than Threat Composer's limit of {max_len} characters")
    return value


def check_tag(name: str) -> str:
    name = name.strip()
    if not name:
        raise ValueError("check name must not be empty")
    if len(name) > MAX_CHECK_NAME:
        raise ValueError(
            f"check name '{name}' is {len(name)} characters; Threat Composer tags are limited to "
            f"{canonical.TAG_MAX}, so check names can be at most {MAX_CHECK_NAME}"
        )
    return CHECK_TAG_PREFIX + clean_text("check name", name)


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
    """The statement Threat Composer's editor renders from these fields."""
    return canonical.render_statement({
        "threatSource": source,
        "prerequisites": prerequisites,
        "threatAction": action,
        "threatImpact": impact,
        "impactedGoal": [g for g in goals if g],
        "impactedAssets": [a for a in assets if a],
    })


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
    text: Optional[str] = None  # file text as read, to detect non-canonical formatting

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
        source = clean_text("threat source", source, canonical.FIELD_MAX)
        prerequisites = clean_text("prerequisites", prerequisites, canonical.FIELD_MAX)
        action = clean_text("threat action", action, canonical.FIELD_MAX)
        impact = clean_text("threat impact", impact, canonical.FIELD_MAX)
        goals = [clean_text("impacted goal", g, canonical.FIELD_MAX) for g in goals if g.strip()]
        assets = [clean_text("impacted asset", a, canonical.FIELD_MAX) for a in assets if a.strip()]
        tags = [clean_text("tag", t, canonical.TAG_MAX) for t in tags or [] if t.strip()]
        num = self._next_numeric("threats")
        threat: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "numericId": num,
            "displayOrder": num,
            "metadata": [],
            "tags": tags,
            "threatSource": source,
            "prerequisites": prerequisites,
            "threatAction": action,
            "threatImpact": impact,
            "impactedGoal": goals,
            "impactedAssets": assets,
            "statement": compose_statement(source, prerequisites, action, impact, goals, assets),
            "status": "threatIdentified",
        }
        if stride:
            bad = [x for x in stride if x.upper() not in STRIDE]
            if bad:
                raise ValueError(f"invalid STRIDE values {bad}; use letters from STRIDE")
            set_metadata(threat, "STRIDE", [x.upper() for x in stride])
        if priority:
            set_metadata(threat, "Priority", priority.capitalize())
        if comments:
            set_metadata(threat, "Comments", clean_text("comments", comments, canonical.FREE_TEXT_SMALL_MAX))
        self.data.setdefault("threats", []).append(threat)
        return threat

    def add_mitigation(
        self, content: str, checks: Optional[List[str]] = None, comments: Optional[str] = None
    ) -> Dict[str, Any]:
        content = clean_text("mitigation content", content, canonical.FREE_TEXT_SMALL_MAX)
        tags = [check_tag(c) for c in checks or []]
        num = self._next_numeric("mitigations")
        mitigation: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "numericId": num,
            "displayOrder": num,
            "metadata": [],
            "tags": tags,
            "content": content,
            "status": "mitigationIdentified",
        }
        if comments:
            set_metadata(mitigation, "Comments", clean_text("comments", comments, canonical.FREE_TEXT_SMALL_MAX))
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
        tag = check_tag(check)
        tags = mitigation.setdefault("tags", [])
        if tag not in tags:
            tags.append(tag)

    def waive(self, threat: Dict[str, Any], reason: str) -> None:
        threat["status"] = WAIVED
        existing = metadata_value(threat, "Comments")
        note = f"Accepted risk: {clean_text('reason', reason)}"
        text = f"{existing}\n\n{note}".strip() if existing else note
        if canonical._u16len(text) > canonical.FREE_TEXT_SMALL_MAX:
            raise ValueError(f"Comments would exceed Threat Composer's {canonical.FREE_TEXT_SMALL_MAX} character limit")
        set_metadata(threat, "Comments", text)

    def canonical_text(self) -> str:
        """The file text Threat Composer would write for this model."""
        canon, report = canonical.canonicalize(self.data)
        if canon is None:
            raise ValueError("Threat Composer would reject this model:\n  " + "\n  ".join(report.errors))
        return canonical.dumps(canon)

    def save(self, root: str) -> None:
        text = self.canonical_text()
        full = os.path.join(root, self.path)
        os.makedirs(os.path.dirname(full) or ".", exist_ok=True)
        with open(full, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)  # no trailing newline: JSON.stringify doesn't add one
        self.text = text


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
    return Model(path, data, text)


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
    """Threat Composer's own schema (errors mean the editor refuses the file), TDD's
    referential checks, and whether the file is in Threat Composer's canonical form."""
    issues: List[Issue] = []

    def err(msg: str) -> None:
        issues.append(Issue(model.path, "error", msg))

    def warn(msg: str) -> None:
        issues.append(Issue(model.path, "warning", msg))

    canon, report = canonical.canonicalize(model.data)
    for e in report.errors:
        err(f"Threat Composer would refuse this file: {e}")
    for u in report.uncertain:
        warn(f"markup Threat Composer will rewrite unpredictably; rephrase: {u}")
    for c in report.changes:
        warn(f"Threat Composer will rewrite this text on open (rephrase, or run tdd fmt): {c}")
    if report.errors:
        return issues

    def unique(items: List[Dict[str, Any]], kind: str) -> set:
        ids, nums = set(), set()
        for item in items:
            iid = item.get("id")
            if iid in ids:
                err(f"duplicate {kind} id {iid}")
            ids.add(iid)
            num = item.get("numericId")
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
        if t.get("status") == WAIVED and not str(metadata_value(t, "Comments") or "").strip():
            err(f"{label} is marked not-useful (waived) but has no Comments explaining why")

    known = set(known_checks) if known_checks is not None else None
    for m in model.mitigations:
        label = mitigation_label(m)
        if not str(m.get("content") or "").strip():
            err(f"{label} has no content")
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

    if canon is not None and model.text is not None and canonical.dumps(canon) != model.text:
        warn(NOT_CANONICAL)
    return issues


NOT_CANONICAL = (
    "not in Threat Composer's canonical format, so opening it in the VS Code extension will "
    "rewrite it; run `tdd fmt`"
)
