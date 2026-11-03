---
name: threat-driven-development
description: Work threat-first in repositories that use Threat Driven Development (a .tdd/config.json and AWS Threat Composer .tc.json threat models). Use when changing code in such a repo, when the tdd Stop hook, lint or CI gate fails, when adding threats, mitigations, checks or risk strategies, when updating threat or mitigation status, or when deciding whether a change needs a threat model update or a no-threat-delta declaration.
---

# Threat Driven Development

Threat Driven Development (TDD) applies the test-driven loop to security. A threat statement is a
failing test. It stays **red** until its risk is handled: usually a linked mitigation whose
**check** passes. Every merge to main must carry a threat model change or an explicit, justified
"no threat delta" declaration.

The CLI is `bin/tdd` in this plugin (`python3 "${CLAUDE_PLUGIN_ROOT}/bin/tdd"`); the SessionStart
context prints its absolute path. Below it is written as `tdd`.

## The loop

1. **Red.** Before or while writing code that changes attack surface, add the threat and choose
   how its risk will be handled:
   ```
   tdd add-threat --source "authenticated tenant user" --prerequisites "who can guess another tenant's invoice id" \
     --action "fetch another tenant's invoice PDF" --impact "disclosure of billing data" \
     --goal confidentiality --asset "invoices" --stride I --priority High --strategy mitigate
   ```
2. **Mitigate.** Add the mitigation, linked to the threat and to a named check:
   ```
   tdd add-mitigation --threat T-4 --content "Invoice lookups are scoped by tenant_id from the session" \
     --check invoice-tenant-scope
   ```
3. **Prove it.** Write the check (usually a test that fails while the mitigation is missing) and
   register it:
   ```
   tdd add-check invoice-tenant-scope --run "pytest -q tests/test_invoices.py::test_cross_tenant_denied"
   ```
4. **Sync, then commit with the code.** `tdd sync` runs the checks and moves statuses along with
   the work. Commit its model change **in the same commit as the implementation**.

If the change truly adds no attack surface, declare it instead, specifically:
```
tdd declare "Extracts the CSV formatter into its own module; same inputs, outputs and callers."
```

## Risk handling strategy: required before a threat is resolved

A threat is resolved only when it carries exactly one strategy tag. This matches Threat Composer's
definition of `threatResolved` ("all agreed risk response actions (mitigation, transfer, avoidance,
risk acceptance) have been completed"):

| tag | resolved when | set with |
|---|---|---|
| `risk:mitigate` | a linked mitigation's checks all pass | `tdd strategy --threat T-4 mitigate` |
| `risk:accept` | a reason is recorded in Comments | `tdd strategy --threat T-4 accept "<why the residual risk is acceptable>"` |
| `risk:transfer` | a reason names who carries the risk | `tdd strategy --threat T-4 transfer "<who, under what agreement>"` |
| `risk:avoid` | a reason says how it is avoided | `tdd strategy --threat T-4 avoid "<what was removed or redesigned>"` |

A threat that doesn't apply at all is dismissed rather than resolved:
`tdd dismiss --threat T-4 "<why it doesn't apply>"`. That sets Threat Composer's "Not Useful" status.

## States and statuses

| TDD state | meaning |
|---|---|
| red | no mitigation or check, a failing check, a resolved mitigation that regressed, or no strategy tag |
| unverified | linked checks exist but have not been run in this tree |
| green | `risk:mitigate` and a linked mitigation's checks all pass |
| handled | `risk:accept`, `risk:transfer` or `risk:avoid` with a reason |
| dismissed | not applicable, with a reason |

Statuses record progress. `tdd sync` sets them from the checks, and CI fails when they disagree
(`policy.status_sync`):

| status | set when |
|---|---|
| mitigation `mitigationIdentified` | planned; no check yet, or not started |
| mitigation `mitigationInProgress` | its check exists and still fails (`tdd sync`, or `tdd progress`) |
| mitigation `mitigationResolved` | all its checks pass (`tdd sync` only; never by hand) |
| mitigation `mitigationResolvedWillNotAction` | decided against, with a reason (`tdd progress ... will-not-action "<why>"`) |
| threat `threatResolved` | green or handled under one strategy tag |

A failing check on an in-progress mitigation is the expected red test. On a resolved mitigation
it's a regression: the threat turns red and CI fails.

## Mitigation tags

The commit that resolves a mitigation gets an annotated git tag, `<model>/M-<n>`: for example
`billing/M-3` for M-3 in `threats/billing.tc.json`. The
post-commit hook creates it, and CI tags `main` after squash merges. To get it right, commit the
`tdd sync` status change together with the implementation. Don't create, move or delete these
tags by hand; `tdd tag` manages them.

## Mitigation priority

Every mitigation carries one `priority:high`, `priority:medium` or `priority:low` tag: the
highest `Priority` among the threats it's linked to. Not-applicable threats don't count, and a
mitigation with no prioritized threat gets no tag. The tag is derived: `tdd` sets it on every save,
and `tdd sync --no-checks` repairs it after hand edits. Don't set it yourself. Change the threat's
Priority, then sync. A stale tag is lint error TDD150. Work on `priority:high` mitigations first.

## Schema and lint

`tdd lint` validates every model against the official Threat Composer JSON Schema (vendored with
the plugin; `tdd schema` shows it) and the editor's own stricter rules, then lints for TDD rules
and model quality. `tdd lint --schema-only` checks only schema and editor compatibility.
`tdd lint --rules` lists rule codes, and `--strict` fails on warnings. Fix errors before
committing, and fix warnings unless there's a reason not to.

## What counts as a delta

Added, removed or changed threats, mitigations, assumptions, links, statuses or tags. Reformatting
a `.tc.json` or renumbering does not count. Paths in `ignore` (docs, markdown by default) never
need a delta. `.tdd/config.json` is always treated as code, and CI reads policy from the base
branch so a change cannot weaken its own gate.

## Declarations

Three accepted forms, all checked for substance (minimum length, no boilerplate like "n/a"):
- a file under `.tdd/declarations/` added by the change (`tdd declare "..."`), preferred for audit
- a commit trailer `No-Threat-Delta: <reason>`
- in CI, a `No-Threat-Delta: <reason>` line in the PR body

## Rules for the agent

- Do not write a declaration just to make the Stop hook or CI pass. If the change touches inputs,
  outputs, auth, secrets, dependencies, data stores, permissions, network exposure or CI, model it.
- Pick a risk strategy deliberately. Choose `risk:accept`, `risk:transfer` or `risk:avoid` only
  when the user agrees, and write a reason specific to the threat.
- Never set `mitigationResolved` or `threatResolved` by hand. `tdd sync` sets them from the checks
  and strategy tags, in the same commit as the work.
- Do not delete threats unless the feature they describe is removed; say so in the commit message.
- Prefer updating or linking an existing threat over adding a near-duplicate.
- A failing check is a failing test: fix the code or the check, not the model.
- For a non-trivial change, ask the `threat-reviewer` agent for proposals first.

## Editing `.tc.json` directly

Prefer the CLI: it writes files in the exact form the Threat Composer VS Code editor saves, so a
human opening the file there doesn't get a dirty, rewritten file. For anything the CLI doesn't
cover (assumptions, architecture text, dataflow), edit the JSON. After each edit the PostToolUse
hook validates the file and reformats it to that canonical form, then tells you to re-read it.

Threat Composer is strict, and these rules keep a file openable and stable:
- No unknown keys anywhere. Metadata keys are limited (threats: `Comments`, `STRIDE`, `Priority`;
  mitigations and assumptions: `Comments`), plus any key starting with `custom:`.
- No `&` or stray `<` or `>` in plain-text fields: Threat Composer shows `&` as `&amp;`, so
  write "and". For placeholders, use curly braces (`{api key}`). Threat Composer would delete an
  angle-bracket tag like `<api key>`, so tdd converts any it finds to braces. Markdown
  descriptions may use `>`.
- Tags are at most 30 characters, so check names are at most 24.
- Link ids are full 36-character UUIDs.

The format is summarized in [threat-composer-format.md](threat-composer-format.md). Run
`tdd fmt` after any bulk edit; CI fails on files that aren't in canonical form.

## Useful commands

```
tdd status [--run-checks]          state per threat, strategy, mitigation progress
tdd sync [--dry-run] [--no-checks]  run checks; update statuses and mitigation priority tags
tdd strategy --threat T-n <mitigate|accept|transfer|avoid> ["reason"]
tdd dismiss --threat T-n "reason"  not applicable
tdd progress --mitigation M-n <identified|in-progress|resolved|will-not-action> ["reason"]
tdd lint [--schema-only] [--strict]  official schema + editor rules + lint
tdd gate [--staged|--head REF]     does this change carry a delta or declaration?
tdd delta                          semantic diff of the threat model vs the base branch
tdd check [--threat T-n]           run linked checks
tdd link --mitigation M-2 --threat T-5 --check name
tdd fmt [--check]                  rewrite models exactly as the Threat Composer editor saves them
tdd tag [--base REV | --all] [--dry-run]  git-tag commits that resolved mitigations
```
