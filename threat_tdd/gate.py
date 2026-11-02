"""The merge rule: a change that touches code must carry a threat model delta
or a justified 'no threat delta' declaration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from threat_tdd import declare, delta as delta_mod, globs, gitutil
from threat_tdd.config import CONFIG_PATH, DECLARATIONS_DIR, STATE_DIR, Config
from threat_tdd.model import Issue, load_all, validate


@dataclass
class GateResult:
    base: Optional[str]
    head: str
    code_changes: List[str] = field(default_factory=list)
    model_changes: List[str] = field(default_factory=list)
    ignored_changes: List[str] = field(default_factory=list)
    delta: delta_mod.Delta = field(default_factory=delta_mod.Delta)
    declarations: List[declare.Declaration] = field(default_factory=list)
    issues: List[Issue] = field(default_factory=list)
    passed: bool = False
    satisfied_by: str = ""  # no-code-changes | model-delta | declaration
    reason: str = ""

    @property
    def errors(self) -> List[Issue]:
        return [i for i in self.issues if i.level == "error"]

    @property
    def valid_declarations(self) -> List[declare.Declaration]:
        return [d for d in self.declarations if d.valid]

    def as_dict(self) -> Dict[str, object]:
        return {
            "passed": self.passed,
            "satisfied_by": self.satisfied_by,
            "reason": self.reason,
            "base": self.base,
            "head": _source_name(self.head),
            "code_changes": self.code_changes,
            "model_changes": self.model_changes,
            "ignored_changes": self.ignored_changes,
            "delta": [c.as_dict() for c in self.delta.changes],
            "declarations": [d.as_dict() for d in self.declarations],
            "issues": [i.__dict__ for i in self.issues],
        }


def _source_name(source: str) -> str:
    return {gitutil.INDEX: "index", gitutil.WORKTREE: "worktree"}.get(source, source)


def classify(cfg: Config, path: str) -> str:
    if globs.match_any(path, cfg.models):
        return "model"
    if path.startswith(DECLARATIONS_DIR + "/") or path.startswith(STATE_DIR + "/"):
        return "ignored"
    if path == CONFIG_PATH:
        return "code"  # policy changes are security relevant
    if globs.match_any(path, cfg.ignore):
        return "ignored"
    return "code"


def default_base(root: str, cfg: Config, explicit: Optional[str] = None) -> Optional[str]:
    """Merge base of HEAD and the configured base branch, as a commit sha."""
    if not gitutil.has_commits(root):
        return None
    ref = gitutil.resolve_base(root, cfg["base_branch"], explicit)
    if ref is None:
        return None
    return gitutil.merge_base(root, ref, "HEAD") or None


def run(
    root: str,
    cfg: Config,
    base: Optional[str],
    head: str,
    extra_messages: Optional[List[str]] = None,
    pr_body: Optional[str] = None,
) -> GateResult:
    if base is None:
        files = gitutil.list_files(root, head if head != gitutil.INDEX else gitutil.INDEX)
        changed = sorted(files)
        dlt = delta_mod.empty_source_delta(root, head, cfg.models)
    else:
        if head not in (gitutil.INDEX, gitutil.WORKTREE):
            mb = gitutil.merge_base(root, base, head)
            base = mb or base
        changed = gitutil.changed_files(root, base, head)
        dlt = delta_mod.compute(root, base, head, cfg.models)

    result = GateResult(base=base, head=head, delta=dlt)
    for path in changed:
        kind = classify(cfg, path)
        {"model": result.model_changes, "code": result.code_changes}.get(kind, result.ignored_changes).append(path)

    # Validate the models this change touches.
    head_models = load_all(root, head, cfg.models)
    touched = set(result.model_changes)
    for path, msg in head_models.errors:
        if path in touched:
            result.issues.append(Issue(path, "error", msg))
    for m in head_models.models:
        if m.path in touched:
            result.issues.extend(validate(m, cfg.checks.keys()))

    result.declarations = declare.collect(
        root,
        base or "",
        head,
        changed,
        cfg.min_declaration_length,
        extra_messages=extra_messages,
        pr_body=pr_body,
    )

    if result.errors:
        result.passed = False
        result.reason = "threat model files touched by this change are invalid"
    elif not result.code_changes:
        result.passed, result.satisfied_by = True, "no-code-changes"
        result.reason = "no code changes that require a threat review"
    elif not dlt.empty:
        result.passed, result.satisfied_by = True, "model-delta"
        result.reason = f"threat model changed ({len(dlt.changes)} change(s))"
    elif result.valid_declarations:
        result.passed, result.satisfied_by = True, "declaration"
        result.reason = "justified no-threat-delta declaration: " + result.valid_declarations[0].origin
    else:
        result.passed = False
        bad = [d for d in result.declarations if not d.valid]
        if bad:
            result.reason = "declaration rejected: " + bad[0].problem
        elif result.model_changes:
            result.reason = "threat model files changed but nothing semantic changed (formatting only)"
        else:
            result.reason = "code changed without a threat model delta or a no-threat-delta declaration"
    return result


def render(result: GateResult, verbose: bool = False) -> str:
    lines = [("PASS" if result.passed else "FAIL") + f": {result.reason}"]
    if result.code_changes:
        shown = result.code_changes if verbose else result.code_changes[:10]
        lines.append(f"code changes ({len(result.code_changes)}):")
        lines += [f"  {p}" for p in shown]
        if len(shown) < len(result.code_changes):
            lines.append(f"  ... {len(result.code_changes) - len(shown)} more")
    if result.delta.changes:
        lines.append(f"threat model delta ({len(result.delta.changes)}):")
        lines += [f"  {c}" for c in result.delta.changes]
    for d in result.declarations:
        mark = "ok" if d.valid else f"rejected ({d.problem})"
        lines.append(f"declaration [{d.origin}] {mark}: {d.text[:120]}")
    for issue in result.issues:
        lines.append(f"  {issue}")
    if not result.passed and not result.errors:
        lines.append("")
        lines.append(HOW_TO_FIX)
    return "\n".join(lines)


HOW_TO_FIX = """To fix, do one of:
  * update the threat model (threats, mitigations or links in a .tc.json file), e.g.
      tdd add-threat --source "..." --action "..." --impact "..." --goal integrity --asset "..."
  * declare why no threat model change is needed:
      tdd declare "Reason this change adds no new attack surface, data flow or trust boundary"
    or add a commit trailer:  No-Threat-Delta: <reason>"""
