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
    --goal confidentiality --asset invoices --stride I --priority High
added T-4 ... state: red (no mitigation yet)

$ tdd add-mitigation --threat T-4 --content "Invoice lookups are scoped by the session tenant" --check invoice-scope
$ tdd add-check invoice-scope --run "pytest -q tests/test_invoices.py::test_cross_tenant_denied"
$ tdd status --run-checks
  GREEN  T-4    An authenticated tenant user who can guess an invoice id can fetch another tenant's invoice ...
```

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
```

`tdd hooks install --shared` writes the hooks to a committed `.githooks/` directory instead and
sets `core.hooksPath`. Existing hooks are preserved and chained. Teams on the
[pre-commit](https://pre-commit.com) framework can use the `tdd-commit-msg` and `tdd-pre-push`
hook ids from `.pre-commit-hooks.yaml`.

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

## What the gate checks

1. **Delta or declaration.** If the change touches any path not in `ignore`, it must change the
   threat model semantically (threats, mitigations, assumptions or links; reformatting does not
   count) or include a valid declaration.
2. **Valid models.** Every `.tc.json` must parse and validate: unique ids, links that resolve,
   known statuses, waived threats carry a reason.
3. **Red policy** (`policy.red`), CI only:
   - `block-new` (default): threats added by the change must be green, and any failing linked check
     fails the build. Pre-existing unmitigated threats are reported, not blocking, so you can adopt
     this on a repo with a backlog.
   - `block`: any red threat fails. `warn`: never fails on red.

CI reads policy from the **base** branch, so a PR cannot loosen its own gate. Check definitions
come from the head so new checks can land with the code they test.

## Works with the Threat Composer editor

`tdd` writes `.tc.json` files in exactly the form the Threat Composer editor in the
[AWS Toolkit for VS Code](https://marketplace.visualstudio.com/items?itemName=AmazonWebServices.aws-toolkit-vscode)
saves them. Opening a model there to read it doesn't dirty the file. Without this, the editor
rewrites files on open: it reorders keys, re-sorts lists as you browse the Threats, Mitigations
and Assumptions views, strips `<tags>` and escapes `&`.

- `tdd fmt` rewrites models into that form, and `tdd fmt --check` only reports.
- CI fails on unformatted models (`policy.format`: `block`, `warn` or `off`).
- When the agent edits a model, the plugin reformats it right away. If the agent wrote text
  Threat Composer would strip or escape, the plugin asks it to rephrase instead.
- The CLI refuses `<`, `>` and `&` in threat and mitigation text, and check names longer than 24
  characters (tags are capped at 30).
- Canonical files have no trailing newline. If an editor or a pre-commit end-of-file fixer adds
  one, `tdd fmt --check` fails. Exclude `*.tc.json` from it (this repo's `.editorconfig` shows how).

## Configuration: `.tdd/config.json`

```json
{
  "base_branch": "main",
  "models": ["threats/**/*.tc.json"],
  "ignore": ["**/*.md", "docs/**", "LICENSE*", ".gitignore"],
  "declaration": { "min_length": 30 },
  "policy": { "red": "block-new", "config_from_base": true, "format": "block" },
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
tdd status [--run-checks] [--json]       red / unverified / green / waived per threat
tdd gate [--staged | --head REF] [--base REF]
tdd delta                                semantic model diff vs the base branch
tdd check [NAMES] [--threat T-n] [--all]
tdd ci --base origin/main [--no-checks]  the full CI gate
tdd declare "<reason>"
tdd add-threat | add-mitigation | link | waive | add-check
tdd validate [PATHS]
tdd fmt [PATHS] [--check]                write models exactly as the Threat Composer editor does
tdd hooks install|uninstall [--shared]
```

## This repo gates itself

`threats/tdd.tc.json` models threats to this tool (PR-body injection into CI, policy weakening,
boilerplate declarations, commands smuggled through model files, hooks executing repo code,
skipped local hooks, an agent gaming the Stop hook, the editor silently rewriting a model). Each mitigation links to a unit test, and
`.github/workflows/ci.yml` runs the action against this repository.

See [docs/design.md](docs/design.md) for the design decisions behind v0.
