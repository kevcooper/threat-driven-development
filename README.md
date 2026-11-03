# Threat Driven Development

Every merge to `main` carries a threat model change, or an explicit, justified "no threat delta"
declaration. Threat models live in the repo as [AWS Threat Composer](https://github.com/awslabs/threat-composer)
`.tc.json` files.

It works like test driven development. A threat statement is a failing test: it is **red** until a
mitigation exists and that mitigation links to a **check** that passes.

| layer | keeps honest | how |
|---|---|---|
| Claude Code plugin | the agent, while it writes code | SessionStart context, `.tc.json` validation after each edit, a Stop hook that won't end the turn until the change carries a delta or declaration |
| git hooks | humans, at commit and push | `commit-msg` (advisory by default), `pre-push` (blocking by default) |
| GitHub Action | everyone | `tdd ci` on every PR. Nobody can skip it. |

All three call the same `tdd` CLI (Python 3.9+, standard library only, nothing to install).

## The loop

```console
$ tdd add-threat --source "authenticated tenant user" --prerequisites "who can guess an invoice id" \
    --action "fetch another tenant's invoice" --impact "disclosure of billing data" \
    --goal confidentiality --asset invoices --stride I --priority High --strategy mitigate
added T-4 ... state: red (no mitigation yet)

$ tdd add-mitigation --threat T-4 --content "Invoice lookups are scoped by the session tenant" --check invoice-scope
$ tdd add-check invoice-scope --run "pytest -q tests/test_invoices.py::test_cross_tenant_denied"
$ tdd sync
threats/billing.tc.json: M-2 mitigationInProgress -> mitigationResolved (its checks pass (invoice-scope))
threats/billing.tc.json: T-4 threatIdentified -> threatResolved (it is green (verified by invoice-scope))
$ git commit -am "Scope invoice lookups by tenant"   # code and status changes in one commit
```

### Risk handling strategy

A threat is resolved only under exactly one explicit strategy tag. This matches Threat Composer's
own definition of "Resolved": all agreed risk responses (mitigation, transfer, avoidance,
acceptance) are complete.

| tag | resolved when |
|---|---|
| `risk:mitigate` | a linked mitigation's checks all pass |
| `risk:accept` | a reason is recorded in the threat's Comments |
| `risk:transfer` | a reason names who carries the risk |
| `risk:avoid` | a reason says what was removed or redesigned |

Set it with `tdd strategy --threat T-4 <strategy> ["reason"]`. A threat that doesn't apply at all
is dismissed instead: `tdd dismiss --threat T-4 "reason"` sets Threat Composer's "Not Useful".

### Progress tracking

Threat Composer's status fields track progress, and `tdd sync` keeps them in step with the checks:

- mitigations: `mitigationIdentified` (planned) → `mitigationInProgress` (its check exists and
  fails) → `mitigationResolved` (its checks pass). `tdd progress` sets in-progress or
  will-not-action (with a reason) by hand. `resolved` is only ever set when the checks pass.
- threats: `threatIdentified` → `threatResolved` once green or handled under a strategy tag.

Each mitigation also carries a `priority:high|medium|low` tag: the highest Priority of the
threats it's linked to, so work can be ordered by what it protects. `tdd` sets it on every save,
and `tdd sync --no-checks` repairs it after edits in the editor. A stale tag fails lint (TDD150).

The statuses change in the same commit as the work. CI (`policy.status_sync`) fails when a status
lags behind the checks, or claims more than they prove. A failing check on an in-progress
mitigation is the expected red test. On a resolved mitigation it's a regression.

When a change genuinely adds no attack surface:

```console
$ tdd declare "Extracts the CSV formatter into its own module; same inputs, outputs and callers."
wrote .tdd/declarations/2026-11-02-feature-csv-refactor.md (commit it with your change)
```

or use a commit trailer `No-Threat-Delta: <reason>`, or put that line in the PR body. Boilerplate
("n/a", "none", "trivial") and short reasons are rejected.

## Install

### Claude Code plugin

It is published in the [kevcooper marketplace](https://github.com/kevcooper/claude-plugins):

```
/plugin marketplace add kevcooper/claude-plugins
/plugin install tdd@kevcooper
```

The plugin is inert in repos without `.tdd/config.json`, so it is safe to install globally. It adds:

- `/tdd:status`, `/tdd:model`, `/tdd:declare`, `/tdd:check`
- the `threat-driven-development` skill (workflow, file format, rules for the agent)
- the `threat-reviewer` agent, which reads a diff and proposes threats, mitigations and checks
- hooks: SessionStart, PostToolUse (`Edit|Write|MultiEdit`), Stop

### In a repository

```console
$ git clone https://github.com/kevcooper/threat-driven-development ~/.tdd-src   # or pip install git+https://...
$ ~/.tdd-src/bin/tdd init --hooks
created .tdd/config.json
created threats/<repo>.tc.json
installed .git/hooks/commit-msg
installed .git/hooks/pre-push
installed .git/hooks/post-commit
```

`tdd hooks install --shared` writes the hooks to a committed `.githooks/` directory instead and
sets `core.hooksPath`. Existing hooks are preserved and chained. Teams on the
[pre-commit](https://pre-commit.com) framework can use the `tdd-commit-msg`, `tdd-pre-push` and
`tdd-post-commit` hook ids from `.pre-commit-hooks.yaml`.

### GitHub Action

```yaml
on:
  pull_request:
    types: [opened, synchronize, reopened, edited]   # edited: re-run when the PR body changes
jobs:
  threat-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: kevcooper/threat-driven-development@main
        with:
          run-checks: true
```

Then make `threat-gate` a required status check on `main`. The job writes a summary table of the
delta, declarations and per-threat state.

To tag `main` after merges (see [Mitigation tags](#mitigation-tags)), add a job that runs only on
pushes to `main`, so pull requests never get a write token:

```yaml
  tag-mitigations:
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: kevcooper/threat-driven-development@main
        with:
          tag-mitigations: "true"
```

### Mitigation tags

The commit that resolves a mitigation is where it landed, since the status flips in the same
commit as the code. `tdd` marks that commit with an annotated git tag:

```console
$ git show mitigation/billing/M-2
tag mitigation/billing/M-2
M-2 resolved: Invoice lookups are scoped by the session tenant

Model: threats/billing.tc.json
Threat: T-4 (High): An authenticated tenant user who can guess an invoice id can fetch ...
Checks: invoice-scope
Priority: high
```

- **Created by:** the `post-commit` hook (`tdd hooks install`), which also sets
  `push.followTags` so the tags go out with a normal `git push`. Run `tdd tag` to tag by hand:
  `--base REV` covers a range, `--all` the whole history, and `--dry-run` and `--push` do what
  they say.
- **Amends and rebases:** an amended or rebased commit moves the tag to the new commit.
- **Squash merges** create new commits on `main`, so tag `main` in CI with
  `tag-mitigations: "true"` (above). Branch tags then move to the squashed commit. With merge
  commits, the branch commit that did the work keeps its tag.
- **Regressions:** a mitigation that is resolved, regresses and is resolved again gets
  `mitigation/billing/M-2-r2` on the later commit.
- **Turn it off** with `"tags": {"mitigations": false}` in `.tdd/config.json`, or change the
  prefix with `"prefix"`.

## What the gate checks

1. **Delta or declaration.** If the change touches any path not in `ignore`, it must change the
   threat model semantically (threats, mitigations, assumptions or links; reformatting does not
   count) or include a valid declaration.
2. **Valid models.** Every `.tc.json` passes the official Threat Composer JSON Schema, the
   editor's own stricter rules, and the TDD rules (unique ids, links that resolve, one strategy
   tag on resolved threats, reasons where required). See `tdd lint`.
3. **Red policy** (`policy.red`), CI only:
   - `block-new` (default): threats added by the change must be green, and any failing linked check
     fails the build. Pre-existing unmitigated threats are reported, not blocking, so you can adopt
     this on a repo with a backlog.
   - `block`: any red threat fails. `warn`: never fails on red.

CI reads policy from the **base** branch, so a PR cannot loosen its own gate. Check definitions
come from the head so new checks can land with the code they test.

## Schema validation and lint

`tdd lint` checks every model against the official Threat Composer JSON Schema (vendored in
`threat_tdd/schemas/`, Apache-2.0) and the editor's stricter load rules, then lints it:

```console
$ tdd lint
threats/billing.tc.json: T-3 error TDD110: marked threatResolved without a risk strategy tag; ...
threats/billing.tc.json: M-5 warning TDD120: not linked to any threat
1 model(s): 1 error(s), 1 warning(s)
```

- `--schema-only` runs only the schema and editor-compatibility rules (`TC001` to `TC004`).
- `--strict` makes warnings fail.
- `--disable TDD130,TDD131` skips rules; `lint.disable` in the config does the same permanently.
- `--rules` lists every rule.
- `tdd validate` runs the error rules the gate, hooks and CI use.
- `tdd schema` prints the schema's path, and `--export PATH` copies it (e.g. for editor validation).

## Works with the Threat Composer editor

`tdd` writes `.tc.json` files in exactly the form the Threat Composer editor in the
[AWS Toolkit for VS Code](https://marketplace.visualstudio.com/items?itemName=AmazonWebServices.aws-toolkit-vscode)
saves them. Opening a model there to read it doesn't dirty the file. Without this, the editor
rewrites files on open: it reorders keys, re-sorts lists as you browse the Threats, Mitigations
and Assumptions views, strips `<tags>` and escapes `&`.

- `tdd fmt` rewrites models into that form, and `tdd fmt --check` only reports.
- CI fails on unformatted models (`policy.format`: `block`, `warn` or `off`).
- Angle-bracket tags the editor would delete are kept as curly braces: `<api key>` becomes
  `{api key}` and `<b>bold</b>` becomes `{b}bold{/b}`. `tdd fmt`, the CLI and the agent hook all
  do this, and the editor leaves braces alone.
- When the agent edits a model, the plugin reformats it right away. If the agent wrote text
  Threat Composer would escape (`&`, or a stray `<` or `>`), the plugin asks it to rephrase.
- The CLI refuses `&` and stray `<` or `>` in threat and mitigation text, and check names longer
  than 24 characters (tags are capped at 30).
- Canonical files have no trailing newline. If an editor or a pre-commit end-of-file fixer adds
  one, `tdd fmt --check` fails. Exclude `*.tc.json` from it (this repo's `.editorconfig` shows how).

## Configuration: `.tdd/config.json`

```json
{
  "base_branch": "main",
  "models": ["threats/**/*.tc.json"],
  "ignore": ["**/*.md", "docs/**", "LICENSE*", ".gitignore"],
  "declaration": { "min_length": 30 },
  "policy": { "red": "block-new", "config_from_base": true, "format": "block", "status_sync": "block" },
  "lint": { "disable": [] },
  "hooks": { "commit_msg": "warn", "pre_push": "block", "claude_stop": "block" },
  "checks": {
    "invoice-scope": { "run": "pytest -q tests/test_invoices.py::test_cross_tenant_denied", "timeout": 300 }
  }
}
```

Mitigations point at checks with a `check:<name>` tag, which you can also edit in the Threat
Composer UI. Mitigations never contain commands.

## CLI reference

```
tdd init [--hooks] [--shared-hooks]      set up config and a starter model
tdd status [--run-checks] [--json]       state per threat, strategy, mitigation progress
tdd sync [--dry-run] [--no-checks]       run checks; update statuses and mitigation priority tags
tdd lint [PATHS] [--schema-only] [--strict] [--disable CODES] [--rules]
tdd schema [--print | --export PATH]     the vendored official Threat Composer schema
tdd strategy --threat T-n <mitigate|accept|transfer|avoid> ["reason"]
tdd dismiss --threat T-n "reason"        not applicable (Not Useful)
tdd progress --mitigation M-n <identified|in-progress|resolved|will-not-action> ["reason"]
tdd gate [--staged | --head REF] [--base REF]
tdd delta                                semantic model diff vs the base branch
tdd check [NAMES] [--threat T-n] [--all] [--resolve]
tdd ci --base origin/main [--no-checks]  the full CI gate
tdd declare "<reason>"
tdd add-threat [--strategy S] | add-mitigation | link | waive | add-check
tdd validate [PATHS]
tdd fmt [PATHS] [--check]                write models exactly as the Threat Composer editor does
tdd tag [--base REV | --all] [--dry-run] [--push]   git-tag commits that resolved mitigations
tdd hooks install|uninstall [--shared]
```

## This repo gates itself

`threats/tdd.tc.json` models threats to this tool (PR-body injection into CI, policy weakening,
boilerplate declarations, commands smuggled through model files, hooks executing repo code,
skipped local hooks, an agent gaming the Stop hook, the editor silently rewriting a model, a
mitigation status that misstates what is implemented, a threat resolved without a recorded risk
strategy, a model the editor refuses to open, injection or token leaks through mitigation tagging). Each mitigation links to a unit test, and
`.github/workflows/ci.yml` runs the action against this repository.

See [docs/design.md](docs/design.md) for the design decisions behind v0.
