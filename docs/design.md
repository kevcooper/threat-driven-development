# Design notes (v0)

The build handoff fixed the goal (delta-or-declaration on every merge, Threat Composer files,
red-until-checked threats) and the three deliverables (plugin, `tdd` CLI, GitHub Action). These are
the decisions made where it was silent.

## One CLI, three enforcement points

The plugin hooks, git hooks and the Action all shell out to `bin/tdd`. Rules live in one place, so
the agent, a human's laptop and CI cannot disagree. The CLI is Python 3.9+ standard library only so
it runs from a plugin checkout, a git hook or a runner without an install step.

## Linking mitigations to checks

Threat Composer has no field for "the test that proves this". TDD uses mitigation **tags**
(`check:<name>`) because tags round-trip through the Threat Composer UI, so humans can maintain
links without the CLI. The tag holds a name, and the command lives in `.tdd/config.json`. Model
files therefore can't carry shell, and the only place commands come from is a file the gate already
treats as code.

## What "red" means and when it blocks

- Red: no linked mitigation, no check tag, an undefined check, or a failing check.
- Unverified: linked checks exist but were not run in this tree. Hooks never run checks (see below),
  so locally most threats show unverified until `tdd status --run-checks`.
- Default CI policy `block-new`: new threats must be green, and failing checks always fail. This
  mirrors TDD (you can't merge a red test) without making adoption impossible on a repo with an
  existing backlog of unmitigated threats.

## Statuses track progress; strategy tags record the decision

Threat Composer's status fields carry progress, and TDD gives each status one meaning:
- **Mitigations:** `mitigationInProgress` means its check exists and fails. `mitigationResolved`
  means the checks pass. `mitigationResolvedWillNotAction` needs a reason.
- **Threats:** `threatResolved` means green or handled under exactly one risk strategy tag
  (`risk:mitigate`, `risk:accept`, `risk:transfer`, `risk:avoid`). Accept, transfer and avoid
  need a written reason. This mirrors Threat Composer's own definition of Resolved ("all agreed
  risk response actions (mitigation, transfer, avoidance, risk acceptance) have been completed").
- **Not Useful** means not applicable, also with a reason. v0's `tdd waive` used it for accepted
  risk, which contradicted that definition. `waive` now records `risk:accept`.

Tags are used for the strategy because they show and edit in the Threat Composer UI and survive
its strict schema. A `custom:` metadata key would also survive, but it's less visible.

`tdd sync` updates statuses from the check results, and the change lands in the same commit as
the code. CI (`policy.status_sync`, default `block`) fails when a status lags behind the checks
or claims more than they prove. In-progress is informational and never fails CI.

The status also sharpens red and green. A failing check on a planned mitigation is expected (it is
the test written before the code) and doesn't override another verified mitigation. A failing
check on a resolved mitigation is a regression and always turns the threat red. The flip is
enforced per pull request, since hooks never run checks.

## Declarations

Three forms (file, commit trailer, PR body) because teams differ: files give an audit trail that
survives squash merges, trailers suit commit-by-commit workflows, and the PR body suits reviewers.
All are judged the same way (minimum length, boilerplate list). That catches laziness, not bad
faith. The reviewer still has to read it. The CI summary shows every declaration so review is easy.

## Trust boundaries

- **CI policy comes from the base branch.** A PR that edits `.tdd/config.json` is gated by the old
  policy. Check *definitions* come from the head, since the PR's code runs in CI anyway and new
  mitigations need new checks.
- **Hooks never execute checks.** Opening an untrusted repo with the plugin installed must not run
  that repo's commands. SessionStart and Stop read cached results only.
- **PR body via env.** The Action never interpolates `${{ }}` inside its `run:` script.

## Claude Code hook behaviour

- **SessionStart** injects counts, the branch's gate state and the workflow. It also snapshots the
  tree fingerprint (HEAD, diff, untracked files).
- **PostToolUse** validates a `.tc.json` or `.tdd/config.json` right after it is edited and feeds
  errors back to the agent.
- **Stop** blocks only if this session changed the tree (fingerprint differs) and the gate fails.
  This avoids nagging a user who opens Claude on a branch just to ask a question. It respects
  `stop_hook_active` so it blocks at most once per turn, and `hooks.claude_stop` can be set to
  `warn` or `off`.
- Every handler is a silent no-op without `.tdd/config.json`, and any internal error exits 0 so a
  bug can't wedge the agent.

## Git hooks

`post-commit` tags commits that resolve mitigations and never fails a commit. During a rebase it
does nothing, and `tdd tag` settles tags afterwards. `commit-msg` defaults to warn because TDD
often commits a red threat first. `pre-push` defaults to
block and evaluates the whole branch against the merge base. Both can be bypassed with
`--no-verify`, which is why CI exists. Known gap: `commit-msg` cannot see an `--amend`'s full
change, only the newly staged part. Pre-push and CI cover it.

## Mitigation tags mark where each mitigation landed

Because a mitigation's status flips to resolved in the same commit as its implementation, that
commit is a precise, permanent marker. `tdd` puts an annotated tag there, `tdd/<model>/M-<n>`,
whose message records the threats, checks, priority and the mitigation's UUID. `M-<n>` is the id
people see in Threat Composer. It's unique only within a model, so the model's file name scopes
it. The file name is used rather than the application name inside the model, because people
rename applications and the tags should stay put. That answers
"when and how was this mitigated?" from git alone, without the model file.

- **Where tags come from:** the post-commit hook tags new commits. `tdd tag` covers ranges, and
  CI uses it on `main`.
- **History rewrites:** a tag moves when its commit is rewritten (amend, rebase, squash: the same
  event on a new commit). A merged branch commit keeps its tag. A later re-resolution, after a
  regression, gets `tdd/<model>/M-<n>-rN`, judged by whether the earlier tag is already in mainline
  history. A name already held by a different mitigation (same file name in two folders) or by a
  tag tdd didn't create is never overwritten. That resolution is skipped with a warning.
- **Safety:** tag names come only from the file name, reduced to letters, digits, `.`, `_` and
  `-`, and the integer numericId, and `git check-ref-format` checks them too. Tag text goes to git on stdin. Only a push-to-main job
  gets a write token (T-12).

## CWE describes the weakness; the dictionary keeps it honest

Threat Composer statements describe a threat: source, action and impact. CWE describes the
weakness that makes it possible. The two complement each other, so CWE ids attach to threats as
tags (`CWE-639`), visible and filterable in the editor. Mitigations derive them through their
links, like priority.

The dictionary is bundled, not left to model memory, because the main risk is a confident but
wrong id. It's MITRE's CWE list trimmed by `scripts/build_cwe.py` to id, name, kind, abstraction,
status, MITRE's mapping usage, a short description, alternate terms, Research Concepts parents
and deprecation pointers. That's about 400 KB, versus 19 MB of XML. MITRE's terms allow
redistribution with their copyright notice and license, which ship in `data/CWE-TERMS.md` and
inside `cwe.json`.

The rules follow MITRE's own mapping guidance:
- **Unknown ids are errors.**
- **Deprecated entries** point to their replacement.
- **Discouraged or Prohibited entries** (Pillars, many Classes, groupings, views) get a warning
  listing usable children.
- **A missing CWE is only a warning,** because process threats often have no honest one.
- **Search** ranks name and alternate-term matches above description matches, and favours
  Base and Variant entries. It hides unusable entries, and says when it hid a strong match.

## Mitigation priority is derived, not entered

A mitigation's priority is the highest `Priority` among the threats it is linked to.
Not-applicable threats are excluded, and a mitigation with no prioritized threat gets no tag.
It's stored as a `priority:<level>` tag, because Threat Composer's schema allows `Priority`
metadata only on threats. Tags are also visible and filterable in the editor.

Because it's derived, nobody edits it: every `tdd` save recomputes it, the PostToolUse hook does
the same after agent edits, and `tdd sync --no-checks` catches up after someone changes a threat's
Priority in the editor. Lint rule TDD150 is an error, so a stale tag fails the gate and CI rather
than silently misordering work.

## Official schema and lint

The official `threat-composer-v1.schema.json` is vendored, and `jsonschema_lite.py` validates
against it with the standard library. That validator covers every keyword the schema uses and
raises on any it doesn't support, so a schema update can't be silently half-checked. A test
compares the schema's property order, length limits and enums with `canonical.py`, so the two
can't drift apart.

The schema is a little stricter than the editor (it rejects `workspace` and `displayedStatement`,
which the editor accepts and drops). It is also looser in places the editor enforces at load
(exact 36-character link ids). Lint reports both, under `TC001` and `TC002`.

## Matching the Threat Composer editor byte for byte

Opening a model in the AWS Toolkit's Threat Composer editor could dirty it. The causes, all from
reading the source (awslabs/threat-composer and aws/aws-toolkit-vscode):

1. **Load pipeline.** `sanitize-html` with no allowed tags runs over every string, then strict zod
   schemas rebuild every object in schema key order and drop `displayedStatement`. The export
   rebuilds the top level in a fixed order, fills in missing sections, and drops `workspace` and
   an empty `brainstorm`.
2. **List views sort the shared state in place.** The Threats, Mitigations and Assumptions lists
   start from the context's own array and call `.sort()` on it when no filter is active, so just
   viewing a list reorders the data that gets saved. The threat list also calls `.reverse()` in
   place when the sort is ascending.
3. **Autosave.** Every second the webview compares `JSON.stringify(state, null, 2)` to the file
   text. If they differ and the parsed JSON is not lodash-equal, the Toolkit replaces the whole
   document. A manual save writes any byte difference.

So a semantic change (sorted arrays, stripped tags, added sections) triggers a rewrite, and the
rewrite also brings in key reordering, which is the noise people notice.

`threat_tdd/canonical.py` reproduces steps 1 and 2 and the serializer, and every write goes
through it. The deployed CDN bundle was checked against the repository source for schema key
order and the in-place sorts. Limits of the port:

- `sanitize-html` is reproduced for standard entities and `&`/`<`/`>` escaping. Comments,
  `<!...>`, `<?...>` and non-standard entities are reported as "uncertain" and left alone, never
  guessed at.
- Angle-bracket tags are the one deliberate departure. The editor deletes them, which loses text
  like `<api key>`. `tdd` instead rewrites any span the editor would parse as a tag into curly
  braces (`{api key}`, `{b}bold{/b}`), which the editor leaves alone. The meaning survives, and so
  does the file the next time it's opened. This also removes the raw-text cases (`<script>`)
  whose exact deletion the port didn't reproduce.
- It was validated by reading the source and against the example models in the Threat Composer
  repository, not by running Threat Composer's JavaScript.
- A list re-sorted to a non-default order (e.g. by priority) is a user action and will still
  reorder the file.

The statement text uses Threat Composer's own templates and article rules (the `indefinite`
package), so a CLI-written threat doesn't change when someone opens it in the threat editor.

## Not in v0

- Rendering diagrams or editing in Threat Composer from the CLI.
- Posting PR comments (the Action writes a job summary instead, which needs no write token).
- Mapping changed code paths to specific threats (e.g. "this file is covered by T-4").
- Signed or approver-attributed declarations.
