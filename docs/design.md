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

## Not in v0

- Rendering diagrams or editing in Threat Composer from the CLI.
- Posting PR comments (the Action writes a job summary instead, which needs no write token).
- Mapping changed code paths to specific threats (e.g. "this file is covered by T-4").
- Signed or approver-attributed declarations.
