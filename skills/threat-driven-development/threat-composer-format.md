# Threat Composer `.tc.json` format (the parts TDD uses)

Threat Composer (https://github.com/awslabs/threat-composer) exports a JSON workspace. Its import
schema is strict: an unknown key anywhere makes the editor refuse the whole file. This example is
in canonical form (see below).

```json
{
  "schema": 1,
  "applicationInfo": {
    "name": "Billing",
    "description": "..."
  },
  "architecture": {
    "description": "..."
  },
  "dataflow": {
    "description": "..."
  },
  "assumptions": [
    {
      "id": "3b1c2a4e-5d6f-4a7b-8c9d-0e1f2a3b4c5d",
      "numericId": 1,
      "displayOrder": 1,
      "metadata": [],
      "tags": [],
      "content": "TLS terminates at the load balancer"
    }
  ],
  "mitigations": [
    {
      "id": "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d",
      "numericId": 2,
      "displayOrder": 2,
      "metadata": [],
      "tags": [
        "check:invoice-tenant-scope"
      ],
      "content": "Invoice lookups are scoped by tenant_id from the session",
      "status": "mitigationIdentified"
    }
  ],
  "assumptionLinks": [
    {
      "type": "Threat",
      "assumptionId": "3b1c2a4e-5d6f-4a7b-8c9d-0e1f2a3b4c5d",
      "linkedId": "9f8e7d6c-5b4a-4c3d-8e2f-1a0b9c8d7e6f"
    }
  ],
  "mitigationLinks": [
    {
      "mitigationId": "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d",
      "linkedId": "9f8e7d6c-5b4a-4c3d-8e2f-1a0b9c8d7e6f"
    }
  ],
  "threats": [
    {
      "id": "9f8e7d6c-5b4a-4c3d-8e2f-1a0b9c8d7e6f",
      "numericId": 4,
      "displayOrder": 4,
      "metadata": [
        {
          "key": "STRIDE",
          "value": [
            "I"
          ]
        },
        {
          "key": "Priority",
          "value": "High"
        },
        {
          "key": "Comments",
          "value": "Found in review of PR 212"
        }
      ],
      "tags": [],
      "threatSource": "authenticated tenant user",
      "prerequisites": "who can guess another tenant's invoice id",
      "threatAction": "fetch another tenant's invoice PDF",
      "threatImpact": "disclosure of billing data",
      "impactedGoal": [
        "confidentiality"
      ],
      "impactedAssets": [
        "invoices"
      ],
      "statement": "An authenticated tenant user who can guess another tenant's invoice id can fetch another tenant's invoice PDF, which leads to disclosure of billing data, resulting in reduced confidentiality of invoices",
      "status": "threatIdentified"
    }
  ]
}
```

## Enumerations

- threat `status`: `threatIdentified`, `threatResolved`, `threatResolvedNotUseful`
- mitigation `status`: `mitigationIdentified`, `mitigationInProgress`, `mitigationResolved`,
  `mitigationResolvedWillNotAction` (a will-not-action mitigation does not count toward green)
- `STRIDE` metadata: any of `S`, `T`, `R`, `I`, `D`, `E`
- `Priority` metadata: `High`, `Medium`, `Low`

## Canonical form (what the VS Code editor writes back)

The AWS Toolkit's Threat Composer editor reloads the file through Threat Composer's import code
and, once a second, compares `JSON.stringify(state, null, 2)` with the file. A semantic
difference makes it rewrite the whole file, and a manual save writes any byte difference. To
leave nothing to rewrite, `tdd` writes:

- top-level keys in this order: `schema`, `applicationInfo`, `architecture`, `dataflow`,
  `assumptions`, `mitigations`, `assumptionLinks`, `mitigationLinks`, `threats`, then `brainstorm`
  only if it has items. Missing sections are written as `{}` or `[]`. `workspace` is dropped.
- each object's keys in schema order: threats `id, numericId, displayOrder, metadata, tags,
  threatSource, prerequisites, threatAction, threatImpact, impactedGoal, impactedAssets, statement,
  customTemplate, status`; mitigations `id, numericId, displayOrder, metadata, tags, content,
  status`; assumptions `id, numericId, displayOrder, metadata, tags, content`; assumption links
  `type, assumptionId, linkedId`; metadata `key, value`. `displayedStatement` is dropped.
- arrays in the order the list views leave them (they sort in place): threats by `numericId`
  descending, mitigations and assumptions by `displayOrder` descending. Missing or zero sort first.
- string values as `sanitize-html` leaves them: tags removed, entities decoded, `&`, `<`, `>`
  escaped.
- two-space indentation, non-ASCII characters unescaped, no trailing newline.

`tdd fmt` applies all of this; `tdd fmt --check` reports without writing.

## TDD conventions

- **Mitigation to check:** tag `check:<name>`, where `<name>` is a key under `checks` in
  `.tdd/config.json` (at most 24 characters, since tags are capped at 30). Mitigations never hold
  shell commands.
- **Risk strategy:** exactly one tag `risk:mitigate`, `risk:accept`, `risk:transfer` or
  `risk:avoid` before a threat is `threatResolved`. The last three need a `Comments` reason.
- **Not applicable:** status `threatResolvedNotUseful` plus a `Comments` reason.
- **Progress:** `mitigationInProgress` while a check fails, `mitigationResolved` once it passes,
  `threatResolved` once green or handled. `tdd sync` maintains these.
- **Schema:** the official JSON Schema ships with the plugin (`tdd schema`). `tdd lint` checks
  against it.
- **IDs:** `id` is a UUID and must be unique. `numericId` is the human label (`T-4`, `M-2`). The CLI
  accepts either, or a unique id prefix.
- **Statement grammar:** `A <source> <prerequisites> can <action>, which leads to <impact>,
  resulting in reduced <goals> of <assets>`.
