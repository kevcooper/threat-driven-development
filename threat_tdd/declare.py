"""'No threat delta' declarations.

A change that touches code but not the threat model must say, in words, why
the threat model does not need to change. A declaration can be made three ways:

1. A file under ``.tdd/declarations/`` added or modified by the change
   (``tdd declare "..."`` writes one). This leaves an audit trail in the repo.
2. A commit trailer in any commit of the change::

       No-Threat-Delta: Refactors the CSV exporter; no new inputs, outputs or trust boundaries.

3. In CI only, the same ``No-Threat-Delta:`` line in the pull request body.

Justifications shorter than ``declaration.min_length`` or that are boilerplate
("n/a", "none", "trivial", ...) are rejected.
"""

from __future__ import annotations

import datetime as _dt
import os
import re
from dataclasses import dataclass
from typing import List, Optional

from threat_tdd import gitutil
from threat_tdd.config import DECLARATIONS_DIR

TRAILER_RE = re.compile(r"^\s*No-Threat-Delta\s*:\s*(.*)$", re.IGNORECASE | re.MULTILINE)

BOILERPLATE = {
    "", "-", "n/a", "na", "none", "no", "nothing", "nope", "trivial", "no change", "no changes",
    "not applicable", "no threat delta", "no delta", "no impact", "none needed", "ok", "fine",
    "see above", "see pr", "tbd", "todo", "skip", "wip",
}


@dataclass
class Declaration:
    origin: str  # "file:<path>" | "trailer" | "pr-body"
    text: str
    valid: bool
    problem: str = ""

    def as_dict(self):
        return self.__dict__.copy()


def judge(text: str, min_length: int) -> Optional[str]:
    """Return a reason the justification is not acceptable, or None."""
    cleaned = " ".join(text.split()).strip()
    normalized = cleaned.lower().strip(" .!")
    if normalized in BOILERPLATE:
        return f"'{cleaned or '(empty)'}' is boilerplate, not a justification"
    if len(cleaned) < min_length:
        return f"justification is {len(cleaned)} characters; at least {min_length} required"
    return None


def from_text(text: str, origin: str, min_length: int) -> List[Declaration]:
    out = []
    for match in TRAILER_RE.finditer(text or ""):
        body = match.group(1).strip()
        problem = judge(body, min_length)
        out.append(Declaration(origin, body, problem is None, problem or ""))
    return out


def file_body(text: str) -> str:
    """Strip front matter, headings and the 'Justification:' label from a declaration file."""
    lines = text.splitlines()
    if lines and lines[0].strip() == "---":
        try:
            end = lines[1:].index("---") + 1
            lines = lines[end + 1:]
        except ValueError:
            pass
    keep = []
    for line in lines:
        s = line.strip()
        if s.startswith("#") or s.lower().startswith(("branch:", "date:", "author:")):
            continue
        if s.lower().startswith("justification:"):
            s = s.split(":", 1)[1].strip()
        keep.append(s)
    return " ".join(" ".join(keep).split())


def from_files(root: str, head: str, changed: List[str], min_length: int) -> List[Declaration]:
    out = []
    for path in changed:
        if not path.startswith(DECLARATIONS_DIR + "/"):
            continue
        text = gitutil.read_file(root, head, path)
        if text is None:  # deleted
            continue
        body = file_body(text)
        problem = judge(body, min_length)
        out.append(Declaration(f"file:{path}", body, problem is None, problem or ""))
    return out


def collect(
    root: str,
    base: str,
    head: str,
    changed: List[str],
    min_length: int,
    extra_messages: Optional[List[str]] = None,
    pr_body: Optional[str] = None,
) -> List[Declaration]:
    found = from_files(root, head, changed, min_length)
    messages = list(extra_messages or [])
    if base:
        messages += gitutil.commit_messages(root, base, head)
    for msg in messages:
        found += from_text(msg, "trailer", min_length)
    if pr_body:
        found += from_text(pr_body, "pr-body", min_length)
    return found


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-").lower()
    return slug[:60] or "change"


def write(root: str, justification: str, branch: Optional[str], min_length: int) -> str:
    problem = judge(justification, min_length)
    if problem:
        raise ValueError(problem)
    today = _dt.date.today().isoformat()
    name = f"{today}-{slugify(branch or 'change')}"
    directory = os.path.join(root, DECLARATIONS_DIR)
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, name + ".md")
    n = 2
    while os.path.exists(path):
        path = os.path.join(directory, f"{name}-{n}.md")
        n += 1
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# No threat delta\n\n")
        if branch:
            fh.write(f"Branch: {branch}\n")
        fh.write(f"Date: {today}\n\n")
        fh.write(f"Justification: {' '.join(justification.split())}\n")
    return os.path.relpath(path, root).replace(os.sep, "/")
