"""The ``tdd`` command line. Shared by Claude Code hooks, git hooks and CI."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from threat_tdd import __version__
from threat_tdd import checks as checks_mod
from threat_tdd import ci as ci_mod
from threat_tdd import canonical, claude_hooks, declare, git_hooks, gitutil, status
from threat_tdd import config as config_mod
from threat_tdd import delta as delta_mod
from threat_tdd import gate as gate_mod
from threat_tdd.model import empty_model, load_all, load_file, model_paths, validate, Model


def _root() -> str:
    root = gitutil.repo_root(os.getcwd())
    if not root:
        raise SystemExit("tdd: not inside a git repository")
    return root


def _cfg(root: str) -> config_mod.Config:
    cfg = config_mod.load(root)
    if cfg is None:
        raise SystemExit(f"tdd: {config_mod.CONFIG_PATH} not found. Run `tdd init` first.")
    return cfg


def _print_json(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _head(args) -> str:
    if getattr(args, "staged", False):
        return gitutil.INDEX
    if getattr(args, "head", None):
        return args.head
    return gitutil.WORKTREE


def _base(root: str, cfg: config_mod.Config, args) -> Optional[str]:
    head = _head(args)
    if args.base:
        if not gitutil.rev_exists(root, args.base):
            raise SystemExit(f"tdd: base '{args.base}' not found")
        if head in (gitutil.INDEX, gitutil.WORKTREE):
            return gitutil.merge_base(root, args.base, "HEAD") or args.base
        return args.base
    if head == gitutil.INDEX:
        return "HEAD" if gitutil.has_commits(root) else None
    return gate_mod.default_base(root, cfg)


def _pick_model(root: str, cfg: config_mod.Config, path: Optional[str]) -> Model:
    if path:
        return load_file(root, path)
    paths = model_paths(root, gitutil.WORKTREE, cfg.models)
    if len(paths) == 1:
        return load_file(root, paths[0])
    if not paths:
        raise SystemExit("tdd: no threat model found; run `tdd init` or pass --file")
    raise SystemExit("tdd: several threat models exist; pass --file:\n  " + "\n  ".join(paths))


# ---- commands ------------------------------------------------------------------


def cmd_init(args) -> int:
    root = _root()
    created = []
    if not config_mod.is_initialized(root):
        data = {k: v for k, v in config_mod.DEFAULTS.items()}
        data["base_branch"] = args.base_branch or data["base_branch"]
        data["checks"] = {}
        config_mod.write(root, data)
        created.append(config_mod.CONFIG_PATH)
    gi = os.path.join(root, ".tdd", ".gitignore")
    if not os.path.exists(gi):
        with open(gi, "w", encoding="utf-8") as fh:
            fh.write("state/\n")
        created.append(".tdd/.gitignore")
    decl_keep = os.path.join(root, config_mod.DECLARATIONS_DIR, ".gitkeep")
    if not os.path.exists(decl_keep):
        os.makedirs(os.path.dirname(decl_keep), exist_ok=True)
        open(decl_keep, "w").close()
        created.append(os.path.relpath(decl_keep, root))
    cfg = _cfg(root)
    if not model_paths(root, gitutil.WORKTREE, cfg.models):
        name = args.name or os.path.basename(root)
        rel = f"threats/{declare.slugify(name)}.tc.json"
        m = Model(rel, empty_model(name, args.description or ""))
        m.save(root)
        created.append(rel)
    if args.hooks:
        created += git_hooks.install(root, shared=args.shared_hooks)
    for c in created:
        print(f"created {c}")
    if not created:
        print("already initialized")
    print("\nNext: open the .tc.json in Threat Composer (https://awslabs.github.io/threat-composer) or use"
          " `tdd add-threat`, and define checks in .tdd/config.json.")
    return 0


def cmd_status(args) -> int:
    root = _root()
    cfg = _cfg(root)
    loaded = load_all(root, gitutil.WORKTREE, cfg.models)
    if args.run_checks:
        res = checks_mod.run_many(cfg, status.linked_checks(loaded.models), echo=None if args.json else print)
        results = {k: v.outcome for k, v in res.items()}
    else:
        results = checks_mod.load_cache(root)
    states = status.evaluate(loaded.models, results, cfg.checks.keys())
    if args.json:
        _print_json({"counts": status.counts(states), "threats": [s.as_dict() for s in states],
                     "parse_errors": loaded.errors})
        return 0
    for path, msg in loaded.errors:
        print(f"{path}: {msg}")
    sym = {"green": "GREEN ", "unverified": "UNVER ", "red": "RED   ", "waived": "WAIVED"}
    current = None
    for s in states:
        if s.path != current:
            current = s.path
            print(f"\n{s.path}")
        print(f"  {sym[s.state]} {s.label:6} {s.statement[:100]}")
        print(f"         {s.reason}" + (f"  [mitigations: {', '.join(s.mitigations)}]" if s.mitigations else ""))
    c = status.counts(states)
    print(f"\n{len(states)} threats: {c['red']} red, {c['unverified']} unverified, {c['green']} green, {c['waived']} waived")
    for note in status.inconsistencies(states):
        print(f"warning: {note}")
    if args.run_checks:
        for mi in status.mitigation_status_issues(loaded.models, results):
            print(f"warning: {mi.path}: {mi.message}")
    if not args.run_checks and c["unverified"]:
        print("run `tdd status --run-checks` to verify linked checks")
    return 0


def cmd_validate(args) -> int:
    from threat_tdd.model import Issue
    root = _root()
    cfg = config_mod.load(root)
    patterns = cfg.models if cfg else ["**/*.tc.json"]
    known = cfg.checks.keys() if cfg else None
    issues: List[Issue] = []
    if args.paths:
        for p in args.paths:
            rel = os.path.relpath(os.path.abspath(p), root).replace(os.sep, "/")
            try:
                issues += validate(load_file(root, rel), known)
            except (ValueError, OSError) as exc:
                issues.append(Issue(rel, "error", str(exc)))
    else:
        loaded = load_all(root, gitutil.WORKTREE, patterns)
        issues += [Issue(p, "error", m) for p, m in loaded.errors]
        for m in loaded.models:
            issues += validate(m, known)
    errors = [i for i in issues if i.level == "error"]
    if args.json:
        _print_json([i.__dict__ for i in issues])
    else:
        for i in issues:
            print(i)
        print("valid" if not errors else f"{len(errors)} error(s)")
    return 1 if errors else 0


def format_file(root: str, rel: str, check_only: bool) -> dict:
    """Rewrite one model in Threat Composer's canonical form. Returns a summary dict."""
    full = os.path.join(root, rel)
    with open(full, encoding="utf-8", newline="") as fh:
        text = fh.read()
    res = canonical.format_text(text)
    summary = {
        "path": rel,
        "changed": res.changed,
        "written": False,
        "errors": res.report.errors,
        "uncertain": res.report.uncertain,
        "text_rewrites": res.report.changes,
    }
    if res.text is not None and res.changed and not check_only:
        with open(full, "w", encoding="utf-8", newline="") as fh:
            fh.write(res.text)
        summary["written"] = True
    return summary


def cmd_fmt(args) -> int:
    root = _root()
    cfg = config_mod.load(root)
    if args.paths:
        paths = [os.path.relpath(os.path.abspath(p), root).replace(os.sep, "/") for p in args.paths]
    else:
        paths = model_paths(root, gitutil.WORKTREE, cfg.models if cfg else ["**/*.tc.json"])
    results = [format_file(root, p, args.check) for p in paths]
    if args.json:
        _print_json(results)
    else:
        for r in results:
            if r["errors"]:
                print(f"{r['path']}: Threat Composer would refuse this file; not formatted:")
                print("".join(f"  {e}\n" for e in r["errors"]), end="")
                continue
            state = "formatted" if r["written"] else ("needs formatting" if r["changed"] else "ok")
            print(f"{r['path']}: {state}")
            for c in r["text_rewrites"]:
                print(f"  text rewritten the way Threat Composer would: {c}")
            for u in r["uncertain"]:
                print(f"  left as is, rephrase (Threat Composer's rewrite is not reproduced): {u}")
    bad = any(r["errors"] or r["uncertain"] for r in results)
    unformatted = args.check and any(r["changed"] for r in results)
    return 1 if bad or unformatted else 0


def cmd_delta(args) -> int:
    root = _root()
    cfg = _cfg(root)
    base = _base(root, cfg, args)
    head = _head(args)
    d = delta_mod.compute(root, base, head, cfg.models) if base else delta_mod.empty_source_delta(root, head, cfg.models)
    if args.json:
        _print_json({"base": base, "changes": [c.as_dict() for c in d.changes], "errors": d.errors})
        return 0
    if d.empty:
        print("no threat model delta")
    for c in d.changes:
        print(f"{c.path}: {c}")
    for p, m in d.errors:
        print(f"{p}: {m}")
    return 0


def cmd_gate(args) -> int:
    root = _root()
    cfg = _cfg(root)
    pr_body = os.environ.get(args.pr_body_env) if args.pr_body_env else None
    result = gate_mod.run(root, cfg, _base(root, cfg, args), _head(args), pr_body=pr_body)
    if args.json:
        _print_json(result.as_dict())
    else:
        print(gate_mod.render(result, verbose=args.verbose))
    return 0 if result.passed else 1


def cmd_check(args) -> int:
    root = _root()
    cfg = _cfg(root)
    loaded = load_all(root, gitutil.WORKTREE, cfg.models)
    names = list(args.names)
    if args.threat:
        for m in loaded.models:
            try:
                t = m.find_threat(args.threat)
            except KeyError:
                continue
            from threat_tdd.model import check_names
            for mit in m.mitigations_for(t["id"]):
                names += check_names(mit)
    if not names and not args.threat:
        names = status.linked_checks(loaded.models) if not args.all else list(cfg.checks)
    if not names:
        print("no checks to run")
        return 0
    res = checks_mod.run_many(cfg, names, echo=None if args.json else print)
    outcomes = {k: v.outcome for k, v in res.items()}
    issues = status.mitigation_status_issues(loaded.models, outcomes)
    resolved = []
    if args.resolve:
        by_path = {m.path: m for m in loaded.models}
        touched = set()
        for mi in issues:
            if mi.kind != "lagging":
                continue
            model = by_path[mi.path]
            model.find_mitigation(mi.id)["status"] = status.RESOLVED
            touched.add(mi.path)
            resolved.append(mi)
        for path in sorted(touched):
            by_path[path].save(root)
        issues = [mi for mi in issues if mi not in resolved]
    if args.json:
        _print_json({"checks": [r.as_dict() for r in res.values()],
                     "resolved": [mi.label for mi in resolved],
                     "status_issues": [mi.message for mi in issues]})
    else:
        for r in res.values():
            if r.outcome != "pass":
                print(f"\n--- {r.name} ({r.outcome}) ---\n{r.output[-3000:]}")
        for mi in resolved:
            print(f"{mi.path}: {mi.label} -> {status.RESOLVED} (checks pass: {', '.join(mi.checks)})")
        if resolved:
            print("commit the model change together with the implementation")
        for mi in issues:
            print(f"{mi.path}: {mi.message}")
    return 0 if all(r.outcome == "pass" for r in res.values()) else 1


def cmd_ci(args) -> int:
    root = _root()
    base = args.base
    if not base:
        cfg = _cfg(root)
        base = gitutil.resolve_base(root, cfg["base_branch"])
        if not base:
            raise SystemExit("tdd ci: cannot find the base branch; pass --base")
    pr_body = os.environ.get(args.pr_body_env) if args.pr_body_env else None
    try:
        res = ci_mod.run(root, base, args.head, run_checks=not args.no_checks, pr_body=pr_body,
                         trust_head_config=args.trust_head_config, echo=print if not args.json else None)
    except ValueError as exc:
        print(f"tdd ci: {exc}", file=sys.stderr)
        return 2
    ci_mod.write_summary(res, args.summary)
    if args.json:
        _print_json({"passed": res.passed, "gate": res.gate.as_dict(),
                     "blocking": [s.as_dict() for s in res.blocking],
                     "threats": [s.as_dict() for s in res.states],
                     "issues": [str(i) for i in res.issues]})
    else:
        print(ci_mod.markdown(res))
    return 0 if res.passed else 1


def cmd_declare(args) -> int:
    root = _root()
    cfg = _cfg(root)
    text = " ".join(args.justification)
    try:
        path = declare.write(root, text, gitutil.current_branch(root), cfg.min_declaration_length)
    except ValueError as exc:
        print(f"tdd declare: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {path} (commit it with your change)")
    return 0


def _split(values: Optional[List[str]]) -> List[str]:
    out = []
    for v in values or []:
        out += [x.strip() for x in v.split(",") if x.strip()]
    return out


def cmd_add_threat(args) -> int:
    root = _root()
    cfg = _cfg(root)
    m = _pick_model(root, cfg, args.file)
    t = m.add_threat(
        args.source, args.prerequisites or "", args.action, args.impact or "",
        _split(args.goal), _split(args.asset), stride=_split(args.stride) or None,
        priority=args.priority, comments=args.comments, tags=_split(args.tag),
    )
    m.save(root)
    print(f"added T-{t['numericId']} to {m.path}: {t['statement']}")
    print("state: red (no mitigation yet). Next: tdd add-mitigation --threat "
          f"T-{t['numericId']} --content \"...\" --check <name>")
    return 0


def cmd_add_mitigation(args) -> int:
    root = _root()
    cfg = _cfg(root)
    m = _pick_model(root, cfg, args.file)
    threats = []
    for ref in args.threat or []:
        try:
            threats.append(m.find_threat(ref))
        except KeyError as exc:
            raise SystemExit(f"tdd: {exc.args[0]}")
    mit = m.add_mitigation(args.content, checks=_split(args.check), comments=args.comments)
    for t in threats:
        m.link(mit["id"], t["id"])
    m.save(root)
    linked = ", ".join(f"T-{t.get('numericId')}" for t in threats) or "nothing"
    print(f"added M-{mit['numericId']} to {m.path}, linked to {linked}")
    for c in _split(args.check):
        if c not in cfg.checks:
            print(f"note: check '{c}' is not defined yet; add it under \"checks\" in {config_mod.CONFIG_PATH}")
    return 0


def cmd_link(args) -> int:
    root = _root()
    cfg = _cfg(root)
    m = _pick_model(root, cfg, args.file)
    try:
        mit = m.find_mitigation(args.mitigation)
        t = m.find_threat(args.threat) if args.threat else None
    except KeyError as exc:
        raise SystemExit(f"tdd: {exc.args[0]}")
    if t is not None:
        m.link(mit["id"], t["id"])
    for c in _split(args.check):
        m.add_check_tag(mit, c)
    m.save(root)
    print(f"updated {m.path}")
    return 0


def cmd_waive(args) -> int:
    root = _root()
    cfg = _cfg(root)
    reason = " ".join(args.reason)
    problem = declare.judge(reason, cfg.min_declaration_length)
    if problem:
        print(f"tdd waive: {problem}", file=sys.stderr)
        return 1
    m = _pick_model(root, cfg, args.file)
    try:
        t = m.find_threat(args.threat)
    except KeyError as exc:
        raise SystemExit(f"tdd: {exc.args[0]}")
    m.waive(t, reason)
    m.save(root)
    print(f"waived T-{t.get('numericId')} in {m.path}")
    return 0


def cmd_add_check(args) -> int:
    root = _root()
    _cfg(root)
    path = os.path.join(root, config_mod.CONFIG_PATH)
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    spec = {"run": args.run}
    if args.timeout:
        spec["timeout"] = args.timeout
    if args.description:
        spec["description"] = args.description
    data.setdefault("checks", {})[args.name] = spec
    config_mod.write(root, data)
    print(f"defined check '{args.name}' in {config_mod.CONFIG_PATH}")
    return 0


def cmd_hooks(args) -> int:
    root = _root()
    if args.action == "install":
        for p in git_hooks.install(root, shared=args.shared, force=args.force):
            print(f"installed {p}")
        if args.shared:
            print("set core.hooksPath=.githooks; commit .githooks/ and ask teammates to run "
                  "`git config core.hooksPath .githooks`")
    else:
        removed = git_hooks.uninstall(root)
        print("\n".join(f"removed {p}" for p in removed) or "no tdd hooks installed")
    return 0


# ---- parser --------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tdd", description="Threat Driven Development")
    p.add_argument("--version", action="version", version=f"tdd {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="<command>")

    s = sub.add_parser("init", help="set up .tdd/config.json and a starter threat model")
    s.add_argument("--name")
    s.add_argument("--description")
    s.add_argument("--base-branch")
    s.add_argument("--hooks", action="store_true", help="also install git hooks")
    s.add_argument("--shared-hooks", action="store_true", help="with --hooks: write to .githooks/")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("status", help="red/green state of every threat")
    s.add_argument("--run-checks", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("validate", help="validate threat model files")
    s.add_argument("paths", nargs="*")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_validate)

    def range_args(sp):
        sp.add_argument("--base", help="base ref (default: merge base with the configured base branch)")
        g = sp.add_mutually_exclusive_group()
        g.add_argument("--head", help="head commit (default: the working tree)")
        g.add_argument("--staged", action="store_true", help="compare the index instead of the working tree")
        sp.add_argument("--json", action="store_true")

    s = sub.add_parser("fmt", help="rewrite models exactly as the Threat Composer editor would save them")
    s.add_argument("paths", nargs="*")
    s.add_argument("--check", action="store_true", help="report, don't write; exit 1 if anything would change")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_fmt)

    s = sub.add_parser("delta", help="semantic threat model diff")
    range_args(s)
    s.set_defaults(func=cmd_delta)

    s = sub.add_parser("gate", help="does this change carry a threat delta or a declaration?")
    range_args(s)
    s.add_argument("--pr-body-env", metavar="VAR", help="read a PR body from this environment variable")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(func=cmd_gate)

    s = sub.add_parser("check", help="run checks linked to mitigations")
    s.add_argument("names", nargs="*")
    s.add_argument("--threat", help="only checks linked to this threat")
    s.add_argument("--all", action="store_true", help="every check in the config, linked or not")
    s.add_argument("--resolve", action="store_true",
                   help="set mitigations whose checks all pass to mitigationResolved")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("ci", help="full CI gate: validate, gate, run checks, red policy")
    s.add_argument("--base", help="base ref, e.g. origin/main")
    s.add_argument("--head", default="HEAD")
    s.add_argument("--no-checks", action="store_true")
    s.add_argument("--pr-body-env", metavar="VAR", default="TDD_PR_BODY")
    s.add_argument("--summary", help="append markdown here (default: $GITHUB_STEP_SUMMARY)")
    s.add_argument("--trust-head-config", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_ci)

    s = sub.add_parser("declare", help="record a justified no-threat-delta declaration")
    s.add_argument("justification", nargs="+")
    s.set_defaults(func=cmd_declare)

    s = sub.add_parser("add-threat", help="append a threat using the Threat Composer grammar")
    s.add_argument("--file")
    s.add_argument("--source", required=True, help="threat source, e.g. 'external actor'")
    s.add_argument("--prerequisites", help="e.g. 'with a valid low-privilege account'")
    s.add_argument("--action", required=True, help="e.g. 'read other tenants' invoices'")
    s.add_argument("--impact", help="e.g. 'disclosure of billing data'")
    s.add_argument("--goal", action="append", help="impacted goal(s): confidentiality, integrity, availability")
    s.add_argument("--asset", action="append", help="impacted asset(s)")
    s.add_argument("--stride", action="append", help="STRIDE letters, e.g. I,E")
    s.add_argument("--priority", choices=["High", "Medium", "Low", "high", "medium", "low"])
    s.add_argument("--comments")
    s.add_argument("--tag", action="append")
    s.set_defaults(func=cmd_add_threat)

    s = sub.add_parser("add-mitigation", help="append a mitigation, link it to threats and checks")
    s.add_argument("--file")
    s.add_argument("--content", required=True)
    s.add_argument("--threat", action="append", help="threat to link (T-3, 3 or id prefix); repeatable")
    s.add_argument("--check", action="append", help="check name(s) from .tdd/config.json")
    s.add_argument("--comments")
    s.set_defaults(func=cmd_add_mitigation)

    s = sub.add_parser("link", help="link a mitigation to a threat and/or a check")
    s.add_argument("--file")
    s.add_argument("--mitigation", required=True)
    s.add_argument("--threat")
    s.add_argument("--check", action="append")
    s.set_defaults(func=cmd_link)

    s = sub.add_parser("waive", help="accept a threat's risk with a written reason")
    s.add_argument("--file")
    s.add_argument("--threat", required=True)
    s.add_argument("reason", nargs="+")
    s.set_defaults(func=cmd_waive)

    s = sub.add_parser("add-check", help="define a named check command in .tdd/config.json")
    s.add_argument("name")
    s.add_argument("--run", required=True, help="shell command; exit 0 means pass")
    s.add_argument("--timeout", type=int)
    s.add_argument("--description")
    s.set_defaults(func=cmd_add_check)

    s = sub.add_parser("hooks", help="install or remove the git hooks")
    s.add_argument("action", choices=["install", "uninstall"])
    s.add_argument("--shared", action="store_true", help="write to .githooks/ and set core.hooksPath")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_hooks)

    s = sub.add_parser("git-hook")
    s.add_argument("name")
    s.add_argument("args", nargs="*")
    s.set_defaults(func=lambda a: git_hooks.main(a.name, a.args))

    s = sub.add_parser("claude-hook")
    s.add_argument("event")
    s.set_defaults(func=lambda a: claude_hooks.main(a.event))
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except gitutil.GitError as exc:
        print(f"tdd: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"tdd: {exc}", file=sys.stderr)
        return 1
    except BrokenPipeError:
        return 0
