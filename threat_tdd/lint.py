"""Schema validation and lint rules for Threat Composer models.

Rule codes are stable so they can be disabled in ``.tdd/config.json`` (``lint.disable``).

  TC001  violates the official Threat Composer JSON Schema           error
  TC002  the Threat Composer editor would refuse to open the file      error
  TC003  not in the editor's canonical format (`tdd fmt`)              warning
  TC004  text the editor will strip or escape on open                 warning

  TDD101 duplicate id or numericId                                     error
  TDD102 link to a missing threat, mitigation or assumption           error
  TDD103 threat with no statement and no threat action                 error
  TDD104 statement differs from what the editor renders from fields   warning
  TDD105 check:<name> tag names a check not defined in config         warning
  TDD110 threatResolved without a risk strategy tag                    error
  TDD111 more than one, or an unknown, risk strategy tag              error
  TDD112 risk:accept / transfer / avoid without a Comments reason      error
  TDD113 not-applicable threat without a Comments reason               error
  TDD114 risk:mitigate but no linked mitigation has a check           warning
  TDD120 mitigation not linked to any threat                           warning
  TDD121 will-not-action mitigation without a Comments reason          error
  TDD122 resolved mitigation with no check to prove it                 warning
  TDD150 mitigation's priority:<level> tag missing or stale            error
  TDD130 threat without STRIDE metadata                                warning
  TDD131 threat without Priority metadata                              warning
  TDD132 threat without impacted goal or impacted assets              warning
  TDD140 assumption not linked to anything                             warning

``tdd validate`` runs the errors plus TC003/TC004/TDD105 (the "core" set used by the
gate, hooks and CI). ``tdd lint`` runs everything.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

from threat_tdd import canonical, jsonschema_lite
from threat_tdd import status as st
from threat_tdd.model import Model, check_names, metadata_value, mitigation_label, threat_label

RULES: Dict[str, tuple] = {
    "TC001": ("error", "official schema"),
    "TC002": ("error", "editor would refuse"),
    "TC003": ("warning", "not canonical"),
    "TC004": ("warning", "text rewritten on open"),
    "TDD101": ("error", "duplicate id"),
    "TDD102": ("error", "broken link"),
    "TDD103": ("error", "empty threat"),
    "TDD104": ("warning", "statement drift"),
    "TDD105": ("warning", "undefined check"),
    "TDD110": ("error", "resolved without strategy"),
    "TDD111": ("error", "conflicting strategy"),
    "TDD112": ("error", "strategy without reason"),
    "TDD113": ("error", "dismissed without reason"),
    "TDD114": ("warning", "mitigate without check"),
    "TDD120": ("warning", "orphan mitigation"),
    "TDD121": ("error", "will-not-action without reason"),
    "TDD122": ("warning", "resolved mitigation unproven"),
    "TDD150": ("error", "mitigation priority tag"),
    "TDD130": ("warning", "missing STRIDE"),
    "TDD131": ("warning", "missing priority"),
    "TDD132": ("warning", "missing impact"),
    "TDD140": ("warning", "orphan assumption"),
}
CORE = {code for code, (level, _) in RULES.items() if level == "error"} | {"TC003", "TC004", "TDD105"}
SCHEMA_ONLY = {"TC001", "TC002", "TC003", "TC004"}


@dataclass
class LintIssue:
    code: str
    level: str  # error | warning
    path: str
    where: str
    message: str

    def __str__(self) -> str:
        loc = f" {self.where}" if self.where else ""
        return f"{self.path}:{loc} {self.level} {self.code}: {self.message}"

    def as_dict(self) -> Dict[str, str]:
        return self.__dict__.copy()


def lint_model(
    model: Model,
    known_checks: Optional[Iterable[str]] = None,
    rules: Optional[Iterable[str]] = None,
    disable: Iterable[str] = (),
) -> List[LintIssue]:
    enabled = set(rules if rules is not None else RULES) - set(disable)
    out: List[LintIssue] = []

    def add(code: str, where: str, message: str) -> None:
        if code in enabled:
            out.append(LintIssue(code, RULES[code][0], model.path, where, message))

    # -- Threat Composer compatibility ------------------------------------------------
    canon, report = canonical.canonicalize(model.data)
    for e in report.errors:
        add("TC002", "", f"Threat Composer would refuse this file: {e}")
    if report.errors:
        return out  # nothing else is meaningful on a file the editor won't open
    for e in jsonschema_lite.validate_threat_composer(model.data):
        add("TC001", "", e)
    for c in report.changes:
        add("TC004", "", f"Threat Composer will rewrite this text on open; rephrase: {c}")
    for u in report.uncertain:
        add("TC004", "", f"markup Threat Composer will rewrite unpredictably; rephrase: {u}")
    for b in report.braced:
        add("TC004", "", f"angle-bracket tag the editor would delete; `tdd fmt` keeps it as curly braces: {b}")
    if model.text is not None and canonical.dumps(canon) != model.text:
        add("TC003", "", "not in Threat Composer's canonical format, so opening it in the VS Code "
                         "extension will rewrite it; run `tdd fmt`")

    # -- references ---------------------------------------------------------------------
    def unique(items: List[Dict[str, Any]], kind: str) -> set:
        ids, nums = set(), set()
        for item in items:
            if item.get("id") in ids:
                add("TDD101", "", f"duplicate {kind} id {item.get('id')}")
            ids.add(item.get("id"))
            if item.get("numericId") in nums:
                add("TDD101", "", f"duplicate {kind} numericId {item.get('numericId')}")
            nums.add(item.get("numericId"))
        return ids

    threat_ids = unique(model.threats, "threat")
    mitigation_ids = unique(model.mitigations, "mitigation")
    assumption_ids = unique(model.assumptions, "assumption")
    for l in model.mitigation_links:
        if l.get("mitigationId") not in mitigation_ids:
            add("TDD102", "", f"mitigationLink references unknown mitigation {l.get('mitigationId')}")
        if l.get("linkedId") not in threat_ids:
            add("TDD102", "", f"mitigationLink references unknown threat {l.get('linkedId')}")
    for l in model.assumption_links:
        if l.get("assumptionId") not in assumption_ids:
            add("TDD102", "", f"assumptionLink references unknown assumption {l.get('assumptionId')}")
        if l.get("linkedId") not in threat_ids | mitigation_ids:
            add("TDD102", "", f"assumptionLink references unknown item {l.get('linkedId')}")

    # -- threats ------------------------------------------------------------------------
    linked_mitigations = {l.get("mitigationId") for l in model.mitigation_links}
    for t in model.threats:
        label = threat_label(t)
        statement = str(t.get("statement") or "").strip()
        if not statement and not str(t.get("threatAction") or "").strip():
            add("TDD103", label, "threat has no statement")
        rendered = canonical.render_statement(t)
        if rendered and statement and rendered != statement:
            add("TDD104", label, "statement differs from what Threat Composer renders from the threat "
                                 f"fields, so editing it there will change it: {rendered!r}")
        strats = st.strategies(t)
        status = t.get("status") or st.THREAT_IDENTIFIED
        unknown = [s for s in strats if s not in st.STRATEGIES]
        if len(strats) > 1 or unknown:
            add("TDD111", label, f"needs exactly one risk strategy tag "
                                 f"({', '.join('risk:' + s for s in st.STRATEGIES)}); has {', '.join(st.risk_tags(t))}")
        if status == st.THREAT_RESOLVED and not strats:
            add("TDD110", label, "marked threatResolved without a risk strategy tag; add one with "
                                 "`tdd strategy --threat " + label + " <mitigate|accept|transfer|avoid>`")
        if len(strats) == 1 and strats[0] in ("accept", "transfer", "avoid") and not st.comments(t):
            add("TDD112", label, f"risk:{strats[0]} needs a Comments entry explaining it")
        if status == st.NOT_USEFUL and not st.comments(t):
            add("TDD113", label, "marked not applicable (threatResolvedNotUseful) without a Comments reason")
        if strats == ["mitigate"]:
            mits = [m for m in model.mitigations_for(t.get("id")) if m.get("status") != st.WONT_DO]
            if not any(check_names(m) for m in mits):
                add("TDD114", label, "risk:mitigate but no linked mitigation has a check:<name> tag yet")
        if status != st.NOT_USEFUL:
            if metadata_value(t, "STRIDE") in (None, []):
                add("TDD130", label, "no STRIDE category")
            if not metadata_value(t, "Priority"):
                add("TDD131", label, "no Priority")
            if not t.get("impactedGoal") and not t.get("impactedAssets"):
                add("TDD132", label, "no impacted goal or impacted assets")

    # -- mitigations ----------------------------------------------------------------------
    known = set(known_checks) if known_checks is not None else None
    for m in model.mitigations:
        label = mitigation_label(m)
        names = check_names(m)
        if known is not None:
            for name in names:
                if name not in known:
                    add("TDD105", label, f"references check '{name}' which is not defined in .tdd/config.json")
        if m.get("id") not in linked_mitigations:
            add("TDD120", label, "not linked to any threat")
        if m.get("status") == st.WONT_DO and not st.comments(m):
            add("TDD121", label, "will-not-action without a Comments reason (tdd progress --reason)")
        if m.get("status") == st.RESOLVED and not names:
            add("TDD122", label, "resolved, but no check:<name> tag proves it")

    for m, current, expected in model.priority_tag_drift():
        label = mitigation_label(m)
        have = ", ".join(current) or "no priority tag"
        want = expected or "no priority tag (no linked threat has a Priority)"
        add("TDD150", label, f"has {have}, should have {want}: the highest Priority of its linked "
                             "threats; run `tdd sync --no-checks`")

    # -- assumptions ----------------------------------------------------------------------
    linked_assumptions = {l.get("assumptionId") for l in model.assumption_links}
    for a in model.assumptions:
        if a.get("id") not in linked_assumptions:
            add("TDD140", f"A-{a.get('numericId')}", "not linked to any threat or mitigation")
    return out


def lint(models: List[Model], known_checks=None, rules=None, disable=()) -> List[LintIssue]:
    out: List[LintIssue] = []
    for m in models:
        out += lint_model(m, known_checks, rules, disable)
    return out
