---
description: Run the checks linked to mitigations and report which threats are green
argument-hint: "[check names | --threat T-n | --all]"
allowed-tools: Bash, Read
---

Run `python3 "${CLAUDE_PLUGIN_ROOT}/bin/tdd" check $ARGUMENTS`, then
`python3 "${CLAUDE_PLUGIN_ROOT}/bin/tdd" sync --dry-run` to show which statuses would change, then
`python3 "${CLAUDE_PLUGIN_ROOT}/bin/tdd" status`.

Report each failing check with the relevant part of its output and the threat(s) it leaves red.
A failing check is a failing test: suggest a fix to the code or the check, not to the threat model.
Offer to run `tdd sync`, which sets statuses from the results (in progress, resolved, threat
resolved). Tell the user to commit that model change together with the implementation, not separately.
