---
name: threat-driven-development
description: Work threat-first in repositories that use Threat Driven Development (a .tdd/config.json and AWS Threat Composer .tc.json threat models). Use when changing code in such a repo, when the tdd Stop hook or CI gate fails, when adding threats, mitigations or checks, or when deciding whether a change needs a threat model update or a no-threat-delta declaration.
---

# Threat Driven Development

Threat Driven Development (TDD) applies the test-driven loop to security. A threat statement is a
failing test. It stays **red** until a mitigation exists, is linked to the threat, and links to a
**check** that passes. Every merge to main must carry a threat model change or an explicit,
justified "no threat delta" declaration.

The CLI is `bin/tdd` in this plugin (`python3 "${CLAUDE_PLUGIN_ROOT}/bin/tdd"`); the SessionStart
context prints its absolute path. Below it is written as `tdd`.

## The loop

1. **Red.** Before or while writing code that changes attack surface, add the threat:
   ```
   tdd add-threat --source "authenticated tenant user" --prerequisites "who can guess another tenant's invoice id" \
     --action "fetch another tenant's invoice PDF" --impact "disclosure of billing data" \
     --goal confidentiality --asset "invoices" --stride I --priority High
   ```
2. **Mitigate.** Add the mitigation and link it to the threat and to a named check:
   ```
   tdd add-mitigation --threat T-4 --content "Invoice lookups are scoped by tenant_id from the session" \
     --check invoice-tenant-scope
   ```
3. **Prove it.** Write the check (usually a test that fails if the mitigation is removed) and register it:
   ```
   tdd add-check invoice-tenant-scope --run "pytest -q tests/test_invoices.py::test_cross_tenant_denied"
   ```
4. **Green and resolved.** Once the implementation makes the check pass, run
   `tdd check --resolve`. It sets every mitigation whose checks pass to `mitigationResolved`.
   Commit that model change **in the same commit as the implementation**. A mitigation added
   ahead of its code stays `mitigationIdentified` (or `mitigationInProgress`) until then.

If the change truly adds no attack surface, declare it instead, specifically:
```
tdd declare "Extracts the CSV formatter into its own module; same inputs, outputs and callers."
```

## States

| state | meaning |
|---|---|
| red | no linked mitigation, no `check:` tag, check undefined, or a linked check fails |
| unverified | linked checks exist but have not been run in this tree |
| green | at least one linked mitigation has checks and all pass |

A mitigation's status says whether it is implemented, and its checks prove it:

| mitigation status | checks | meaning |
|---|---|---|
| `mitigationIdentified` / `mitigationInProgress` | failing | planned; the failing check is the red test |
| `mitigationResolved` | passing | implemented and proven |
| `mitigationIdentified` / `mitigationInProgress` | passing | **status lags**: CI fails until `tdd check --resolve` |
| `mitigationResolved` | failing | **regression**: the threat goes red and CI fails |
| waived | status `threatResolvedNotUseful` with a written reason (`tdd waive`) |

CI (`tdd ci`) with the default `block-new` policy fails when a threat added by the change is red,
or when any linked check fails. Older red threats are reported but do not block.

## What counts as a delta

Added, removed or changed threats, mitigations, assumptions, or links. Reformatting a `.tc.json`
or renumbering does not count. Paths in `ignore` (docs, markdown by default) never need a delta.
`.tdd/config.json` is always treated as code, and CI reads policy from the base branch so a change
cannot weaken its own gate.

## Declarations

Three accepted forms, all checked for substance (minimum length, no boilerplate like "n/a"):
- a file under `.tdd/declarations/` added by the change (`tdd declare "..."`), preferred for audit
- a commit trailer `No-Threat-Delta: <reason>`
- in CI, a `No-Threat-Delta: <reason>` line in the PR body

## Rules for the agent

- Do not write a declaration just to make the Stop hook or CI pass. If the change touches inputs,
  outputs, auth, secrets, dependencies, data stores, permissions, network exposure or CI, model it.
- Do not set a threat to `threatResolved` or waive it to turn it green. Green comes from checks.
- Do not set `mitigationResolved` by hand. `tdd check --resolve` sets it when the checks pass,
  and the flip goes in the same commit as the code that implements the mitigation.
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
- No `<`, `>` or `&` in plain-text fields. Threat Composer strips `<tags>` and shows `&` as
  `&amp;`. Write "and", and use words instead of `<placeholders>`. Markdown descriptions may use `>`.
- Tags are at most 30 characters, so check names are at most 24.
- Link ids are full 36-character UUIDs.

The format is summarized in [threat-composer-format.md](threat-composer-format.md). Run
`tdd fmt` after any bulk edit; CI fails on files that aren't in canonical form.

## Useful commands

```
tdd status [--run-checks]     red/green per threat
tdd gate [--staged|--head REF]  does this change carry a delta or declaration?
tdd delta                     semantic diff of the threat model vs the base branch
tdd check [--threat T-n] [--resolve]  run linked checks; --resolve marks proven mitigations resolved
tdd link --mitigation M-2 --threat T-5 --check name
tdd waive --threat T-3 "<specific accepted-risk reason>"
tdd validate
tdd fmt [--check]             rewrite models exactly as the Threat Composer editor saves them
```
