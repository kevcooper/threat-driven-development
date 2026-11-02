"""Gitignore-style glob matching with ``**`` support, on POSIX-style relative paths."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Iterable


@lru_cache(maxsize=256)
def _compile(pattern: str) -> "re.Pattern[str]":
    pattern = pattern.strip().lstrip("/")
    # A pattern with no slash matches at any depth, like .gitignore.
    if "/" not in pattern:
        pattern = "**/" + pattern
    if pattern.endswith("/"):
        pattern += "**"
    out = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def match(path: str, pattern: str) -> bool:
    return bool(_compile(pattern).match(path.replace("\\", "/")))


def match_any(path: str, patterns: Iterable[str]) -> bool:
    return any(match(path, p) for p in patterns)
