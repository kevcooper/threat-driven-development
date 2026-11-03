"""Threat state, risk handling strategy, and status tracking.

A threat is resolved only once it carries exactly one explicit risk handling
strategy tag, matching Threat Composer's own definition of ``threatResolved``
("all agreed risk response actions (mitigation, transfer, avoidance, risk
acceptance) have been completed"):

  risk:mitigate   resolved when a linked mitigation's checks all pass
  risk:accept     resolved with a Comments entry explaining the accepted risk
  risk:transfer   resolved with a Comments entry naming who carries the risk
  risk:avoid      resolved with a Comments entry explaining how it is avoided

TDD state of each threat:

  green       risk:mitigate, and a linked mitigation's checks all pass
  handled     risk:accept / risk:transfer / risk:avoid with a written reason
  dismissed   status threatResolvedNotUseful (not applicable) with a reason
  unverified  linked checks exist but have not been run here
  red         anything else: no mitigation, no check, a failing check, a
              resolved mitigation that regressed, or no strategy tag

Statuses track progress, and ``tdd sync`` keeps them in step with the checks:

  mitigation  identified -> in progress (a check exists and fails)
                         -> resolved    (all its checks pass)
  threat      identified -> resolved    (green or handled)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from threat_tdd.model import (
    Model,
    check_names,
    metadata_value,
    mitigation_label,
    threat_label,
)

GREEN, UNVERIFIED, RED, HANDLED, DISMISSED = "green", "unverified", "red", "handled", "dismissed"
STATES = (RED, UNVERIFIED, GREEN, HANDLED, DISMISSED)

THREAT_IDENTIFIED = "threatIdentified"
THREAT_RESOLVED = "threatResolved"
NOT_USEFUL = "threatResolvedNotUseful"
MIT_IDENTIFIED = "mitigationIdentified"
MIT_IN_PROGRESS = "mitigationInProgress"
RESOLVED = "mitigationResolved"
WONT_DO = "mitigationResolvedWillNotAction"

RISK_TAG_PREFIX = "risk:"
STRATEGIES = ("mitigate", "accept", "transfer", "avoid")
STRATEGY_PAST = {"accept": "accepted", "transfer": "transferred", "avoid": "avoided", "mitigate": "mitigated"}
BAD_OUTCOMES = ("fail", "error", "missing")


def risk_tags(item: Dict) -> List[str]:
    return [t for t in item.get("tags") or [] if isinstance(t, str) and t.lower().startswith(RISK_TAG_PREFIX)]


def strategies(threat: Dict) -> List[str]:
    return [t[len(RISK_TAG_PREFIX):].lower() for t in risk_tags(threat)]


def comments(item: Dict) -> str:
    return str(metadata_value(item, "Comments") or "").strip()


@dataclass
class ThreatState:
    path: str
    id: str
    label: str
    statement: str
    state: str
    reason: str
    failing_checks: List[str] = field(default_factory=list)
    checks: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    declared_status: str = ""
    strategy: Optional[str] = None

    def as_dict(self) -> Dict[str, object]:
        return self.__dict__.copy()


def _verify(mitigations: List[Dict], results: Dict[str, str], known: set):
    """How well the linked mitigations are proven: (kind, reason, failing, checks)."""
    if not mitigations:
        return "no-mitigation", "no mitigation linked", [], []
    all_checks = sorted({c for m in mitigations for c in check_names(m)})
    if not all_checks:
        return "no-checks", "linked mitigations have no check:<name> tag", [], []
    regressed = sorted({c for m in mitigations if m.get("status") == RESOLVED
                        for c in check_names(m) if results.get(c) in BAD_OUTCOMES})
    if regressed:
        return "regressed", "resolved mitigation's check failing: " + ", ".join(regressed), regressed, all_checks
    proven = [m for m in mitigations if check_names(m) and all(results.get(c) == "pass" for c in check_names(m))]
    if proven:
        names = sorted({c for m in proven for c in check_names(m)})
        return "verified", "verified by " + ", ".join(names), [], all_checks
    failing = [c for c in all_checks if results.get(c) in BAD_OUTCOMES]
    if failing:
        return "failing", "check failing: " + ", ".join(failing), failing, all_checks
    undefined = [c for c in all_checks if c not in known]
    if len(undefined) == len(all_checks):
        return "undefined", "check not defined in config: " + ", ".join(undefined), undefined, all_checks
    not_run = [c for c in all_checks if c not in results]
    return "unverified", "checks not run: " + ", ".join(not_run), [], all_checks


def evaluate(models: List[Model], results: Optional[Dict[str, str]], known_checks) -> List[ThreatState]:
    """``results`` maps check name -> outcome; a missing name means 'not run'."""
    results = results or {}
    known = set(known_checks)
    out: List[ThreatState] = []
    for model in models:
        for t in model.threats:
            label = threat_label(t)
            statement = str(t.get("statement") or t.get("threatAction") or "")
            declared = str(t.get("status") or THREAT_IDENTIFIED)
            mitigations = [m for m in model.mitigations_for(t.get("id")) if m.get("status") != WONT_DO]
            m_labels = [mitigation_label(m) for m in mitigations]
            strats = strategies(t)
            strategy = strats[0] if len(strats) == 1 and strats[0] in STRATEGIES else None

            def state(st: str, reason: str, failing=(), checks=()) -> None:
                out.append(ThreatState(model.path, t["id"], label, statement, st, reason,
                                       list(failing), list(checks), m_labels, declared, strategy))

            if declared == NOT_USEFUL:
                if comments(t):
                    state(DISMISSED, "not applicable: " + comments(t)[:80])
                else:
                    state(RED, "dismissed as not applicable without a Comments reason")
                continue
            if len(strats) > 1 or (strats and strategy is None):
                state(RED, f"needs exactly one risk strategy tag ({', '.join('risk:' + s for s in STRATEGIES)}); "
                           f"has {', '.join(risk_tags(t))}")
                continue
            if strategy in ("accept", "transfer", "avoid"):
                if comments(t):
                    state(HANDLED, f"risk {STRATEGY_PAST[strategy]}: " + comments(t)[:80])
                else:
                    state(RED, f"risk:{strategy} needs a Comments entry explaining it")
                continue

            kind, reason, failing, checks = _verify(mitigations, results, known)
            if kind == "verified":
                if strategy == "mitigate":
                    state(GREEN, reason, checks=checks)
                else:
                    state(RED, f"{reason}, but no risk strategy tag; add risk:mitigate "
                               f"(tdd strategy --threat {label} mitigate)", checks=checks)
            elif strategy is None and declared == THREAT_RESOLVED:
                state(RED, "marked threatResolved without a risk strategy tag", failing, checks)
            elif kind == "unverified":
                state(UNVERIFIED, reason, checks=checks)
            else:
                state(RED, reason, failing, checks)
    return out


def linked_checks(models: List[Model]) -> List[str]:
    names = set()
    for model in models:
        linked_ids = {l.get("mitigationId") for l in model.mitigation_links}
        for m in model.mitigations:
            if m.get("id") in linked_ids and m.get("status") != WONT_DO:
                names.update(check_names(m))
    return sorted(names)


def counts(states: List[ThreatState]) -> Dict[str, int]:
    c = {s: 0 for s in STATES}
    for s in states:
        c[s.state] = c.get(s.state, 0) + 1
    return c


def summary(states: List[ThreatState]) -> str:
    c = counts(states)
    return f"{len(states)} threats: " + ", ".join(f"{c[s]} {s}" for s in STATES)


# ---- status tracking ---------------------------------------------------------------


@dataclass
class StatusIssue:
    """A status that disagrees with what the checks and strategy tags say.

    kind:
      lagging    the work is done (checks pass / strategy recorded) but the status
                 still says otherwise; ``tdd sync`` fixes it, CI requires it
      progress   a mitigation's check exists and fails but it is still identified;
                 ``tdd sync`` marks it in progress (informational)
      overclaim  marked resolved, but the checks or strategy don't support it;
                 CI fails, nothing is changed automatically
    """

    entity: str  # threat | mitigation
    path: str
    id: str
    label: str
    kind: str
    current: str
    expected: Optional[str]
    detail: str

    @property
    def message(self) -> str:
        if self.kind == "lagging":
            return (f"{self.label} is {self.current} but {self.detail}; set it to {self.expected} "
                    "in the same change (`tdd sync`)")
        if self.kind == "progress":
            return f"{self.label} has a failing check ({self.detail}); mark it {self.expected} (`tdd sync`)"
        return f"{self.label} is {self.current} but {self.detail}"


def status_issues(models: List[Model], results: Dict[str, str], known_checks) -> List[StatusIssue]:
    """Mitigations are judged only when all their checks ran."""
    out: List[StatusIssue] = []
    for model in models:
        for m in model.mitigations:
            names = check_names(m)
            current = str(m.get("status") or MIT_IDENTIFIED)
            label = mitigation_label(m)
            if current == WONT_DO:
                continue
            if current == RESOLVED and not names:
                out.append(StatusIssue("mitigation", model.path, m["id"], label, "overclaim", current, None,
                                       "it has no check:<name> tag to prove it"))
                continue
            if not names or any(n not in results for n in names):
                continue
            failing = [n for n in names if results[n] != "pass"]
            if not failing and current != RESOLVED:
                out.append(StatusIssue("mitigation", model.path, m["id"], label, "lagging", current, RESOLVED,
                                       f"its checks pass ({', '.join(names)})"))
            elif failing and current == RESOLVED:
                out.append(StatusIssue("mitigation", model.path, m["id"], label, "overclaim", current, None,
                                       f"its check failed ({', '.join(failing)}); fix the implementation or the check"))
            elif failing and current == MIT_IDENTIFIED:
                out.append(StatusIssue("mitigation", model.path, m["id"], label, "progress", current,
                                       MIT_IN_PROGRESS, ", ".join(failing)))

    for s in evaluate(models, results, known_checks):
        if s.state in (GREEN, HANDLED) and s.declared_status != THREAT_RESOLVED:
            why = f"it is {s.state} ({s.reason})"
            out.append(StatusIssue("threat", s.path, s.id, s.label, "lagging", s.declared_status,
                                   THREAT_RESOLVED, why))
        elif s.state == RED and s.declared_status == THREAT_RESOLVED:
            out.append(StatusIssue("threat", s.path, s.id, s.label, "overclaim", s.declared_status, None,
                                   f"it is red ({s.reason})"))
    return out


def apply_status_fixes(models: List[Model], issues: List[StatusIssue]) -> List[StatusIssue]:
    """Apply lagging and progress fixes in memory. Returns the issues applied."""
    by_path = {m.path: m for m in models}
    applied = []
    for i in issues:
        if i.kind not in ("lagging", "progress") or i.expected is None:
            continue
        model = by_path[i.path]
        item = model.find_mitigation(i.id) if i.entity == "mitigation" else model.find_threat(i.id)
        item["status"] = i.expected
        applied.append(i)
    return applied
