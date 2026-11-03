"""Red / green state of each threat.

  green       at least one linked mitigation has checks, and all of them pass
  unverified  a linked mitigation has checks, but they have not been run here
  red         no linked mitigation with a check, a referenced check is undefined,
              or a linked check failed (a failing "test")
  waived      status threatResolvedNotUseful with a written justification
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from threat_tdd.model import (
    WAIVED,
    WONT_DO,
    Model,
    check_names,
    mitigation_label,
    threat_label,
)

GREEN, UNVERIFIED, RED, WAIVED_STATE = "green", "unverified", "red", "waived"
RESOLVED = "mitigationResolved"


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

    def as_dict(self) -> Dict[str, object]:
        return self.__dict__.copy()


def evaluate(models: List[Model], results: Optional[Dict[str, str]], known_checks) -> List[ThreatState]:
    """``results`` maps check name -> outcome; None or a missing name means 'not run'."""
    results = results or {}
    known = set(known_checks)
    out: List[ThreatState] = []
    for model in models:
        for t in model.threats:
            label = threat_label(t)
            statement = str(t.get("statement") or t.get("threatAction") or "")
            status = str(t.get("status") or "threatIdentified")
            mitigations = [m for m in model.mitigations_for(t.get("id")) if m.get("status") != WONT_DO]
            m_labels = [mitigation_label(m) for m in mitigations]
            all_checks = sorted({c for m in mitigations for c in check_names(m)})

            if status == WAIVED:
                out.append(ThreatState(model.path, t["id"], label, statement, WAIVED_STATE,
                                       "accepted risk", [], all_checks, m_labels, status))
                continue
            if not mitigations:
                out.append(ThreatState(model.path, t["id"], label, statement, RED,
                                       "no mitigation linked", [], [], m_labels, status))
                continue
            if not all_checks:
                out.append(ThreatState(model.path, t["id"], label, statement, RED,
                                       "linked mitigations have no check:<name> tag", [], [], m_labels, status))
                continue

            undefined = [c for c in all_checks if c not in known]
            bad = ("fail", "error", "missing")
            failing = [c for c in all_checks if results.get(c) in bad]
            # A failing check on a resolved (implemented) mitigation is a regression and
            # always red. On a planned mitigation it is expected, like a test written
            # before the code, and doesn't override another verified mitigation.
            regressed = sorted({c for m in mitigations if m.get("status") == RESOLVED
                                for c in check_names(m) if results.get(c) in bad})
            if regressed:
                out.append(ThreatState(model.path, t["id"], label, statement, RED,
                                       "resolved mitigation's check failing: " + ", ".join(regressed),
                                       regressed, all_checks, m_labels, status))
                continue

            # Green if any single mitigation is fully verified.
            green_m = [
                m for m in mitigations
                if check_names(m) and all(results.get(c) == "pass" for c in check_names(m))
            ]
            if green_m:
                out.append(ThreatState(model.path, t["id"], label, statement, GREEN,
                                       "verified by " + ", ".join(sorted({c for m in green_m for c in check_names(m)})),
                                       [], all_checks, m_labels, status))
                continue
            if failing:
                out.append(ThreatState(model.path, t["id"], label, statement, RED,
                                       "check failing: " + ", ".join(failing), failing, all_checks, m_labels, status))
                continue
            if undefined and len(undefined) == len(all_checks):
                out.append(ThreatState(model.path, t["id"], label, statement, RED,
                                       "check not defined in config: " + ", ".join(undefined),
                                       undefined, all_checks, m_labels, status))
                continue
            out.append(ThreatState(model.path, t["id"], label, statement, UNVERIFIED,
                                   "checks not run: " + ", ".join(c for c in all_checks if c not in results),
                                   [], all_checks, m_labels, status))
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
    c = {GREEN: 0, UNVERIFIED: 0, RED: 0, WAIVED_STATE: 0}
    for s in states:
        c[s.state] = c.get(s.state, 0) + 1
    return c


def inconsistencies(states: List[ThreatState]) -> List[str]:
    """Threats a human marked resolved that TDD still considers red."""
    return [
        f"{s.path} {s.label} is marked threatResolved but is red ({s.reason})"
        for s in states
        if s.declared_status == "threatResolved" and s.state == RED
    ]


@dataclass
class MitigationStatusIssue:
    """A mitigation whose declared status disagrees with its checks.

    The rule: a mitigation is ``mitigationResolved`` exactly when it is implemented,
    and "implemented" means its checks pass. The status flips in the same change that
    makes the checks pass, so a mitigation added ahead of its code stays
    ``mitigationIdentified`` (or ``mitigationInProgress``) until then.
    """

    path: str
    id: str
    label: str
    kind: str  # "lagging": checks pass, not resolved | "unproven": resolved, a check fails
    status: str
    checks: List[str]

    @property
    def message(self) -> str:
        if self.kind == "lagging":
            return (
                f"{self.label} checks pass ({', '.join(self.checks)}) but its status is {self.status}; "
                f"set it to {RESOLVED} in the same change that implements it (`tdd check --resolve`)"
            )
        return (
            f"{self.label} is {RESOLVED} but its check failed ({', '.join(self.checks)}); "
            "fix the implementation or the check"
        )


def mitigation_status_issues(models: List[Model], results: Dict[str, str]) -> List[MitigationStatusIssue]:
    """Only mitigations whose checks all ran are judged; others are left alone."""
    out: List[MitigationStatusIssue] = []
    for model in models:
        for m in model.mitigations:
            names = check_names(m)
            current = str(m.get("status") or "")
            if not names or current == WONT_DO or any(n not in results for n in names):
                continue
            failing = [n for n in names if results[n] != "pass"]
            if not failing and current != RESOLVED:
                out.append(MitigationStatusIssue(model.path, m["id"], mitigation_label(m), "lagging",
                                                 current or "(none)", names))
            elif failing and current == RESOLVED:
                out.append(MitigationStatusIssue(model.path, m["id"], mitigation_label(m), "unproven",
                                                 current, failing))
    return out
