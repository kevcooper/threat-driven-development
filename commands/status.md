---
description: Show the red/green state of every threat and whether this branch passes the threat gate
argument-hint: "[--run-checks]"
allowed-tools: Bash
---

Run the Threat Driven Development CLI and report the results. The CLI lives at
`${CLAUDE_PLUGIN_ROOT}/bin/tdd` (the session context also gives its absolute path).

1. Run `python3 "${CLAUDE_PLUGIN_ROOT}/bin/tdd" status $ARGUMENTS`.
2. Run `python3 "${CLAUDE_PLUGIN_ROOT}/bin/tdd" gate`.

Summarize in a few lines: counts of red, unverified, green and waived threats; the red threats and
why each is red; and whether the branch currently passes the gate. If the repo has no
`.tdd/config.json`, say so and offer to run `tdd init`. Do not change any files.
