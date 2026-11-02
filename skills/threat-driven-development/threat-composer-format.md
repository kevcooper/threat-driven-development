# Threat Composer `.tc.json` format (the parts TDD uses)

Threat Composer (https://github.com/awslabs/threat-composer) exports a JSON workspace. TDD reads
and writes these fields and preserves everything else.

```json
{
  "schema": 1,
  "applicationInfo": { "name": "Billing", "description": "..." },
  "architecture": { "description": "..." },
  "dataflow": { "description": "..." },
  "assumptions": [
    { "id": "uuid", "numericId": 1, "content": "TLS terminates at the load balancer", "metadata": [], "tags": [] }
  ],
  "threats": [
    {
      "id": "uuid",
      "numericId": 4,
      "displayOrder": 4,
      "statement": "An authenticated tenant user who can guess another tenant's invoice id can fetch another tenant's invoice PDF, which leads to disclosure of billing data, resulting in reduced confidentiality of invoices",
      "threatSource": "authenticated tenant user",
      "prerequisites": "who can guess another tenant's invoice id",
      "threatAction": "fetch another tenant's invoice PDF",
      "threatImpact": "disclosure of billing data",
      "impactedGoal": ["confidentiality"],
      "impactedAssets": ["invoices"],
      "metadata": [
        { "key": "STRIDE", "value": ["I"] },
        { "key": "Priority", "value": "High" },
        { "key": "Comments", "value": "Found in review of PR #212" }
      ],
      "tags": [],
      "status": "threatIdentified"
    }
  ],
  "mitigations": [
    {
      "id": "uuid",
      "numericId": 2,
      "content": "Invoice lookups are scoped by tenant_id from the session",
      "metadata": [],
      "tags": ["check:invoice-tenant-scope"],
      "status": "mitigationIdentified"
    }
  ],
  "mitigationLinks": [ { "mitigationId": "<mitigation uuid>", "linkedId": "<threat uuid>" } ],
  "assumptionLinks": [ { "assumptionId": "<assumption uuid>", "linkedId": "<threat or mitigation uuid>", "type": "Threat" } ]
}
```

## Enumerations

- threat `status`: `threatIdentified`, `threatResolved`, `threatResolvedNotUseful`
- mitigation `status`: `mitigationIdentified`, `mitigationInProgress`, `mitigationResolved`,
  `mitigationResolvedWillNotAction` (a will-not-action mitigation does not count toward green)
- `STRIDE` metadata: any of `S`, `T`, `R`, `I`, `D`, `E`
- `Priority` metadata: `High`, `Medium`, `Low`

## TDD conventions

- **Mitigation to check:** tag `check:<name>`, where `<name>` is a key under `checks` in
  `.tdd/config.json`. Mitigations never hold shell commands.
- **Waiver:** status `threatResolvedNotUseful` plus a `Comments` metadata entry explaining the
  accepted risk. Validation fails without the comment.
- **IDs:** `id` is a UUID and must be unique. `numericId` is the human label (`T-4`, `M-2`). The CLI
  accepts either, or a unique id prefix.
- **Statement grammar:** `A <source> <prerequisites> can <action>, which leads to <impact>,
  resulting in reduced <goals> of <assets>`.
