---
description: Record a justified "no threat delta" declaration for the current change
argument-hint: "<why this change needs no threat model update>"
allowed-tools: Bash, Read, Grep
---

The user wants to declare that the current change needs no threat model update. Proposed
justification: $ARGUMENTS

Be a skeptical reviewer before writing anything:

1. Look at the change: `python3 "${CLAUDE_PLUGIN_ROOT}/bin/tdd" gate` and the git diff against the base branch.
2. Check whether the change adds or alters any input, output, dependency, data store, secret,
   permission, network call, auth path or trust boundary. If it does, say so and recommend
   `/tdd:model` instead. Do not declare.
3. If the declaration is warranted, make the justification specific to this change: what it does
   and why that leaves attack surface unchanged. Generic text ("refactor", "n/a", "no security
   impact") is rejected by the CLI and is not acceptable here either.
4. Write it with `python3 "${CLAUDE_PLUGIN_ROOT}/bin/tdd" declare "<justification>"` and tell the
   user to commit the new file under `.tdd/declarations/` with the change.
