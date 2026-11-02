"""The CI backstop: validate, gate, run checks, apply the red-threat policy."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from threat_tdd import checks as checks_mod
from threat_tdd import config as config_mod
from threat_tdd import gate as gate_mod
from threat_tdd import gitutil, status
from threat_tdd.model import Issue, load_all, validate


@dataclass
class CIResult:
    passed: bool
    gate: gate_mod.GateResult
    states: List[status.ThreatState]
    blocking: List[status.ThreatState]
    issues: List[Issue]
    check_results: Dict[str, checks_mod.CheckResult]
    config_note: str
    notes: List[str] = field(default_factory=list)


def effective_config(root: str, base: str, trust_head: bool) -> (config_mod.Config, str):
    head_cfg = config_mod.load(root)
    if head_cfg is None:
        raise ValueError(f"{config_mod.CONFIG_PATH} not found; run `tdd init`")
    if trust_head:
        return head_cfg, "policy read from the head commit (--trust-head-config)"
    try:
        base_cfg = config_mod.load(root, base)
    except ValueError:
        base_cfg = None
    if base_cfg is None:
        return head_cfg, "no config on the base branch; using the head config"
    if not base_cfg["policy"].get("config_from_base", True):
        return head_cfg, "base config allows the head config to apply (policy.config_from_base = false)"
    # Policy comes from base so a change cannot weaken its own gate. Check
    # definitions come from head so new checks can be introduced alongside the code
    # they test; those commands run in CI with the same trust as the rest of the PR.
    merged = dict(base_cfg.raw)
    merged["checks"] = head_cfg.raw.get("checks", {})
    note = "policy read from the base branch"
    if {k: v for k, v in head_cfg.raw.items() if k != "checks"} != {k: v for k, v in base_cfg.raw.items() if k != "checks"}:
        note += " (this change modifies .tdd/config.json policy; it takes effect after merge)"
    return config_mod.Config(merged, root, base), note


def run(
    root: str,
    base_ref: str,
    head: str = "HEAD",
    run_checks: bool = True,
    pr_body: Optional[str] = None,
    trust_head_config: bool = False,
    echo=None,
) -> CIResult:
    if not gitutil.rev_exists(root, base_ref):
        raise ValueError(f"base ref '{base_ref}' not found (fetch it, e.g. git fetch origin main)")
    cfg, note = effective_config(root, base_ref, trust_head_config)
    result = gate_mod.run(root, cfg, base_ref, head, pr_body=pr_body)

    head_models = load_all(root, head, cfg.models)
    issues: List[Issue] = [Issue(p, "error", m) for p, m in head_models.errors]
    for m in head_models.models:
        issues.extend(validate(m, cfg.checks.keys()))

    check_results: Dict[str, checks_mod.CheckResult] = {}
    if run_checks:
        check_results = checks_mod.run_many(cfg, status.linked_checks(head_models.models), echo=echo)
    states = status.evaluate(
        head_models.models, {k: v.outcome for k, v in check_results.items()}, cfg.checks.keys()
    )

    new_keys = result.delta.added_threat_keys()
    policy = cfg.red_policy
    blocking: List[status.ThreatState] = []
    for s in states:
        if s.state != status.RED or policy == "warn":
            continue
        if policy == "block" or (s.path, s.id) in new_keys or s.failing_checks:
            blocking.append(s)

    notes = status.inconsistencies(states)
    passed = result.passed and not [i for i in issues if i.level == "error"] and not blocking
    return CIResult(passed, result, states, blocking, issues, check_results, note, notes)


def markdown(res: CIResult) -> str:
    g = res.gate
    icon = {"green": "🟢", "unverified": "🟡", "red": "🔴", "waived": "⚪"}
    out = [f"## Threat Driven Development: {'✅ pass' if res.passed else '❌ fail'}", ""]
    out.append(f"**Gate:** {'pass' if g.passed else 'fail'}: {g.reason}")
    out.append(f"<sub>{res.config_note}</sub>")
    out.append("")
    if g.delta.changes:
        out.append("### Threat model delta")
        out.append("| change | item | detail |")
        out.append("|---|---|---|")
        for c in g.delta.changes:
            out.append(f"| {c.op} | {c.kind} {c.label} | {c.detail.replace('|', '/')} |")
        out.append("")
    if g.declarations:
        out.append("### Declarations")
        for d in g.declarations:
            out.append(f"- {'✅' if d.valid else '❌'} `{d.origin}`: {d.text}" + (f" ({d.problem})" if d.problem else ""))
        out.append("")
    if res.states:
        c = status.counts(res.states)
        out.append(f"### Threats: {c['red']} red, {c['unverified']} unverified, {c['green']} green, {c['waived']} waived")
        out.append("| | threat | state | statement |")
        out.append("|---|---|---|---|")
        blocking = {(s.path, s.id) for s in res.blocking}
        for s in res.states:
            flag = " **(blocking)**" if (s.path, s.id) in blocking else ""
            out.append(f"| {icon.get(s.state, '')} | {s.label} | {s.state}: {s.reason}{flag} | {s.statement[:140].replace('|', '/')} |")
        out.append("")
    errors = [i for i in res.issues if i.level == "error"] + g.errors
    if errors or res.notes:
        out.append("### Problems")
        out += [f"- {i}" for i in errors]
        out += [f"- {n}" for n in res.notes]
        out.append("")
    failed_checks = [r for r in res.check_results.values() if r.outcome != "pass"]
    for r in failed_checks:
        out.append(f"<details><summary>check <code>{r.name}</code>: {r.outcome}</summary>\n\n```\n{r.output[-3000:]}\n```\n</details>")
    if not g.passed and not g.errors:
        out.append("")
        out.append("```\n" + gate_mod.HOW_TO_FIX + "\n```")
    return "\n".join(out) + "\n"


def write_summary(res: CIResult, path: Optional[str]) -> None:
    path = path or os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(markdown(res))
