---
description: Run the checks linked to mitigations and report which threats are green
argument-hint: "[check names | --threat T-n | --all]"
allowed-tools: Bash, Read
---

Run `python3 "${CLAUDE_PLUGIN_ROOT}/bin/tdd" check $ARGUMENTS`, then
`python3 "${CLAUDE_PLUGIN_ROOT}/bin/tdd" status`.

Report each failing check with the relevant part of its output and the threat(s) it leaves red.
A failing check is a failing test: suggest a fix to the code or the check, not to the threat model.
