---
description: Validate threat models against the Threat Composer schema and lint them
argument-hint: "[--schema-only] [--strict] [paths]"
allowed-tools: Bash, Read
---

Run `python3 "${CLAUDE_PLUGIN_ROOT}/bin/tdd" lint $ARGUMENTS`.

Summarize the result by rule code. For each error, say what is wrong and the smallest fix. For
example, add a risk strategy with `tdd strategy`, add a Comments reason, or run `tdd fmt`. Group
warnings and mention them briefly. Don't change files unless the user asks. If they do, prefer
CLI commands (`tdd strategy`, `tdd dismiss`, `tdd progress`, `tdd link`, `tdd fmt`) over editing
JSON by hand, then run lint again.
