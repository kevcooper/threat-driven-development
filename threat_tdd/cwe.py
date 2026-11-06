"""The CWE dictionary bundled with tdd, for describing the weakness behind a threat.

A threat is tagged with the weakness that makes it possible, e.g. ``CWE-639``
(Authorization Bypass Through User-Controlled Key). Mitigations get the CWE tags of
the threats they're linked to, derived like their priority tag.

The data is MITRE's CWE list, trimmed to what tdd needs (see scripts/build_cwe.py and
data/CWE-TERMS.md). It's used to:

  - reject CWE ids that don't exist, so an agent can't invent one
  - flag deprecated entries and point to their replacements
  - warn on entries MITRE marks Discouraged or Prohibited for mapping (Pillars,
    many Classes, groupings, views), suggesting more specific children
  - let the agent search for the right entry instead of recalling it
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Optional, Tuple

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "cwe.json")
TAG_RE = re.compile(r"^CWE-(\d+)$", re.IGNORECASE)
REF_RE = re.compile(r"^(?:CWE-?)?(\d+)$", re.IGNORECASE)
GOOD_USAGE = ("Allowed", "Allowed-with-Review")
STOPWORDS = set("a an and the of to in on for by with or from into is are be can use using via".split())


@lru_cache(maxsize=1)
def _data() -> Dict[str, Any]:
    with open(DATA, encoding="utf-8") as fh:
        return json.load(fh)


def version() -> str:
    d = _data()
    return f"CWE {d['version']} ({d['date']})"


def entries() -> Dict[int, Dict[str, Any]]:
    return {int(k): v for k, v in _data()["entries"].items()}


@lru_cache(maxsize=1)
def _entries() -> Dict[int, Dict[str, Any]]:
    return entries()


def get(cwe_id: int) -> Optional[Dict[str, Any]]:
    return _entries().get(int(cwe_id))


def url(cwe_id: int) -> str:
    return f"https://cwe.mitre.org/data/definitions/{int(cwe_id)}.html"


def tag(cwe_id: int) -> str:
    return f"CWE-{int(cwe_id)}"


def parse_ref(ref: Any) -> int:
    """'CWE-639', 'cwe639' or '639' -> 639."""
    m = REF_RE.match(str(ref).strip())
    if not m:
        raise ValueError(f"'{ref}' is not a CWE id (expected e.g. CWE-639 or 639)")
    return int(m.group(1))


def tag_ids(item: Dict[str, Any]) -> List[int]:
    """CWE ids among an item's tags, in tag order."""
    out = []
    for t in item.get("tags") or []:
        m = TAG_RE.match(t) if isinstance(t, str) else None
        if m:
            out.append(int(m.group(1)))
    return out


def is_cwe_tag(t: Any) -> bool:
    return isinstance(t, str) and bool(TAG_RE.match(t))


@lru_cache(maxsize=1)
def _children() -> Dict[int, List[int]]:
    kids: Dict[int, List[int]] = {}
    for cid, e in _entries().items():
        for p in e.get("parents", []):
            kids.setdefault(p, []).append(cid)
    return {k: sorted(v) for k, v in kids.items()}


def children(cwe_id: int, usable_only: bool = True) -> List[int]:
    kids = _children().get(int(cwe_id), [])
    if usable_only:
        kids = [k for k in kids if (get(k) or {}).get("usage") in GOOD_USAGE and get(k).get("status") != "Deprecated"]
    return kids


def label(cwe_id: int) -> str:
    e = get(cwe_id)
    return f"CWE-{cwe_id}: {e['name']}" if e else f"CWE-{cwe_id}"


def problem(cwe_id: int) -> Optional[Tuple[str, str]]:
    """(severity, message) when an id shouldn't be used to describe a weakness.

    severity is 'unknown', 'deprecated' or 'mapping'.
    """
    e = get(cwe_id)
    if e is None:
        return "unknown", f"CWE-{cwe_id} is not in {version()}"
    if e.get("status") == "Deprecated":
        see = ", ".join(label(s) for s in e.get("see", [])) or "its description on cwe.mitre.org"
        return "deprecated", f"{label(cwe_id)} is deprecated; use {see}"
    usage = e.get("usage")
    if usage in ("Discouraged", "Prohibited"):
        what = {"grouping": "a grouping of weaknesses", "view": "a view"}.get(e["kind"], f"a {e.get('abstraction')}-level entry")
        kids = children(cwe_id)
        hint = ("; more specific: " + ", ".join(label(k) for k in kids[:4])
                + (f" and {len(kids) - 4} more (tdd cwe show {cwe_id})" if len(kids) > 4 else "")) if kids else \
            f"; find a more specific entry with `tdd cwe search`"
        return "mapping", f"{label(cwe_id)} is {what} that MITRE marks {usage} for mapping{hint}"
    return None


def _words(text: str) -> List[str]:
    """Lowercase words; hyphenated words also appear joined ("hard-coded" -> "hardcoded")."""
    low = text.lower()
    joined = re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)+", low)
    words = re.findall(r"[a-z0-9]+", low) + [j.replace("-", "") for j in joined]
    return [w for w in words if w not in STOPWORDS and len(w) > 1]


def search(query: str, limit: int = 10, include_all: bool = False) -> List[Tuple[int, float]]:
    """Rank entries for a free-text query. Unusable entries are excluded unless include_all."""
    q = query.strip()
    m = REF_RE.match(q)
    if m and get(int(m.group(1))):
        return [(int(m.group(1)), 100.0)]
    terms = _words(q)
    if not terms:
        return []
    phrase = " ".join(terms)
    scored = []
    for cid, e in _entries().items():
        if not include_all and (e.get("usage") not in GOOD_USAGE or e.get("status") == "Deprecated"):
            continue
        name = " ".join(_words(e.get("name", "")))
        alts = " ".join(_words(" ".join(e.get("alternate_terms", []))))
        desc = " ".join(_words(e.get("description", "")))
        score = 0.0
        for t in terms:
            if re.search(rf"\b{re.escape(t)}", name):
                score += 3
            if re.search(rf"\b{re.escape(t)}", alts):
                score += 3
            if re.search(rf"\b{re.escape(t)}", desc):
                score += 1
        if score == 0:
            continue
        if phrase in name or phrase in alts:
            score += 4
        matched = sum(1 for t in terms if re.search(rf"\b{re.escape(t)}", name + " " + alts + " " + desc))
        score *= matched / len(terms)  # favour entries that cover the whole query
        score += {"Base": 0.5, "Variant": 0.3}.get(e.get("abstraction"), 0)
        scored.append((cid, round(score, 2)))
    scored.sort(key=lambda x: (-x[1], x[0]))
    return scored[:limit]


def describe(cwe_id: int) -> Dict[str, Any]:
    e = dict(get(cwe_id) or {})
    e["id"] = int(cwe_id)
    e["url"] = url(cwe_id)
    e["children"] = children(cwe_id, usable_only=False)
    return e


def derived_tags(threats: Iterable[Dict[str, Any]]) -> List[str]:
    """Sorted, de-duplicated CWE tags across threats."""
    ids = sorted({i for t in threats for i in tag_ids(t)})
    return [tag(i) for i in ids]
