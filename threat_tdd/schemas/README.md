# Vendored Threat Composer schema

`threat-composer-v1.schema.json` is the official JSON Schema for Threat Composer's
`.tc.json` data exchange format, copied unmodified from
[awslabs/threat-composer](https://github.com/awslabs/threat-composer)
`schemas/threat-composer-v1.schema.json` at commit
`744ae2bfc3d600b0cfba35ad0dd6822cf77cc182`.

Threat Composer is Copyright Amazon.com, Inc. or its affiliates, licensed under the
Apache License 2.0 (see `LICENSE-threat-composer`).

`tdd lint` / `tdd validate` check models against it. To update, copy the newer file
over this one, update the commit above, and run the tests:
`tests/test_schema.py` fails if `threat_tdd/canonical.py` no longer agrees with the
schema's fields, key order or length limits.
