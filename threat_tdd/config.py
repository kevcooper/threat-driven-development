"""Repository configuration, stored at ``.tdd/config.json``."""

from __future__ import annotations

import copy
import json
import os
from typing import Any, Dict, Optional

from threat_tdd import gitutil

CONFIG_PATH = ".tdd/config.json"
DECLARATIONS_DIR = ".tdd/declarations"
STATE_DIR = ".tdd/state"

DEFAULTS: Dict[str, Any] = {
    "version": 1,
    # The branch every change is measured against.
    "base_branch": "main",
    # Where Threat Composer models live.
    "models": ["threats/**/*.tc.json"],
    # Changes to these paths never require a threat delta. Model files and
    # declarations are always excluded. Keep this list short: .tdd/config.json
    # and CI workflows are deliberately NOT ignored.
    "ignore": ["**/*.md", "docs/**", "LICENSE*", ".gitignore"],
    "declaration": {"min_length": 30},
    "policy": {
        # block      every red threat fails CI
        # block-new  red threats added by the change, and threats whose checks fail, fail CI;
        #            pre-existing unmitigated threats only warn (default)
        # warn       red threats never fail CI
        "red": "block-new",
        # When true, CI reads policy from the base branch so a PR cannot weaken its own gate.
        "config_from_base": True,
    },
    "hooks": {
        "commit_msg": "warn",  # off | warn | block
        "pre_push": "block",  # off | warn | block
        "claude_stop": "block",  # off | warn | block
    },
    # name -> {"run": "<shell command>", "timeout": seconds, "description": "..."}
    "checks": {},
}


def _merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict) and key != "checks":
            out[key] = _merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


class Config:
    def __init__(self, data: Dict[str, Any], root: str, origin: str = "worktree"):
        self.raw = data
        self.data = _merge(DEFAULTS, data)
        self.root = root
        self.origin = origin

    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    @property
    def models(self):
        return list(self.data["models"])

    @property
    def ignore(self):
        return list(self.data["ignore"])

    @property
    def checks(self) -> Dict[str, Dict[str, Any]]:
        out = {}
        for name, spec in (self.data.get("checks") or {}).items():
            out[name] = {"run": spec} if isinstance(spec, str) else dict(spec)
        return out

    @property
    def min_declaration_length(self) -> int:
        return int(self.data["declaration"].get("min_length", 30))

    def hook_mode(self, name: str) -> str:
        mode = str(self.data["hooks"].get(name, "warn")).lower()
        return mode if mode in ("off", "warn", "block") else "warn"

    @property
    def red_policy(self) -> str:
        mode = str(self.data["policy"].get("red", "block-new")).lower()
        return mode if mode in ("block", "block-new", "warn") else "block-new"


def is_initialized(root: str) -> bool:
    return os.path.isfile(os.path.join(root, CONFIG_PATH))


def load(root: str, source: str = gitutil.WORKTREE) -> Optional[Config]:
    text = gitutil.read_file(root, source, CONFIG_PATH)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{CONFIG_PATH} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{CONFIG_PATH} must contain a JSON object")
    origin = "worktree" if source == gitutil.WORKTREE else source
    return Config(data, root, origin)


def write(root: str, data: Dict[str, Any]) -> str:
    path = os.path.join(root, CONFIG_PATH)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    return path
