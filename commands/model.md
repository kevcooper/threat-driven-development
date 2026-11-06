---
description: Update the threat model for the current change (threat-first, like writing a failing test)
argument-hint: "[focus, e.g. 'the new webhook endpoint']"
allowed-tools: Bash, Read, Grep, Glob, Edit, Task
---

Bring the threat model up to date with the change on this branch. Focus: $ARGUMENTS

Use the `threat-driven-development` skill. The CLI is `python3 "${CLAUDE_PLUGIN_ROOT}/bin/tdd"`.

1. Run `tdd gate --json` and `git diff $(git merge-base HEAD origin/main 2>/dev/null || git merge-base HEAD main)` to see what changed.
2. Delegate a review to the `threat-reviewer` agent, passing it the list of changed files and the
   threat model path(s). Ask it for candidate threats in Threat Composer grammar, existing threats
   the change affects, and mitigations with a concrete check for each.
3. For each threat you accept, find the weakness behind it with `tdd cwe search` (check it with
   `tdd cwe show`), then add it with `tdd add-threat --cwe <id> --strategy <mitigate|accept|transfer|avoid>`
   (it starts red). Choose accept, transfer or avoid only with the user's agreement, and give a
   specific reason. For a mitigated threat, add the
   mitigation with `tdd add-mitigation --threat T-n --check <name>`. If the check does not exist,
   write it (a test, a lint rule, a config assertion) and register it with `tdd add-check`.
4. Keep threat and mitigation text free of `&` and stray `<` or `>` (Threat Composer escapes
   them). Write placeholders in curly braces, `{name}`. Run `tdd status --run-checks`. For each mitigation the change implements, run
   `tdd sync` so statuses move with the code, in the same commit. Then run `tdd lint` and fix its
   errors. New threats should end green or handled, or stay red with a clear note to the user
   about what is still missing. Never set a resolved status or strategy just to make the gate pass.
5. If after honest review the change has no security-relevant delta, say why and suggest `/tdd:declare`
   instead of inventing threats.

Report what you added, the final red/green state, and anything the user must decide.
