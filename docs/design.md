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

`commit-msg` defaults to warn because TDD often commits a red threat first. `pre-push` defaults to
block and evaluates the whole branch against the merge base. Both can be bypassed with
`--no-verify`, which is why CI exists. Known gap: `commit-msg` cannot see an `--amend`'s full
change, only the newly staged part. Pre-push and CI cover it.

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

- `sanitize-html` is reproduced for tags, standard entities and `&`/`<`/`>` escaping. Comments,
  raw-text tags like `<script>`, quoted attributes and non-standard entities are reported as
  "uncertain" and left alone, never guessed at.
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
