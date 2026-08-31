# Windows Security Hardening

A PowerShell portfolio toolkit for defensive assessment, Windows control verification, security posture reporting, remote-access analysis, and system-integrity review.

## Portfolio intent

This repository demonstrates the ability to translate governance concerns into repeatable technical checks. The scripts are learning and portfolio assets, not a universal production baseline.

## Capability map

```text
GOVERNANCE INTENT
      |
      +--> [Remote Access] -----> Analyze policy and exposed pathways
      |
      +--> [Endpoint Posture] --> Collect configuration evidence
      |
      +--> [System Integrity] --> Identify control conflicts
      |
      +--> [Recommendations] ---> Explain corrective options
      |
      +--> [Evidence] ----------> Produce reviewable output
```

## Two-dimensional metafield view

```text
                         CONTROL LIFECYCLE
                 DISCOVER   ASSESS   EXPLAIN   VERIFY
SECURITY DOMAIN
Remote access       [X]       [X]       [X]       [X]
Endpoint posture    [X]       [X]       [X]       [X]
Secure-site risk    [X]       [X]       [X]       [ ]
Service integrity   [X]       [X]       [X]       [ ]
System conflicts    [X]       [X]       [X]       [X]

METAFIELDS
Input     : Local Windows configuration and service state
Process   : Discovery, comparison, classification, recommendation
Control   : Read-only by default; elevated access where required
Output    : Console or structured security findings
Evidence  : Status, observed value, rationale, recommendation
Risk      : False positives and environment-specific assumptions
Boundary  : Authorized Windows systems only
```

## Included scripts

- `Analyze-RemoteAccessPolicy.ps1`
- `Analyze-SystemRisk-ForSecureSites.ps1`
- `MicrosoftServiceMasquerading.ps1`
- `SecurityPosture_Report.ps1`
- `Verify-RemoteAccessLockdown_WithRecommendations.ps1`
- `WindowsSecurityReview.ps1`
- `WindowsSystemConflictIntegrityReview.ps1`

## Requirements

- Windows 10 or Windows 11
- Windows PowerShell 5.1 or PowerShell 7 where compatible
- Administrator rights for protected configuration checks
- An isolated test environment before operational use

## Safe usage

1. Read the script and its comment-based help.
2. Confirm the script is assessment-only before execution.
3. Run in a test environment.
4. Review reported findings as indicators, not confirmed incidents.
5. Do not apply remediation without an approved change and rollback plan.

## Repository structure

```text
src/       Curated PowerShell scripts
docs/      Architecture, catalog, usage, and control documentation
examples/  Sanitized example outputs
tests/     Pester tests and syntax checks
assets/    Screenshots and exported diagrams
```

## Disclaimer

These scripts are provided for learning, defensive administration, and portfolio demonstration. Validate every control against the target environment and current product documentation.

<!-- OWNERSHIP-AND-LICENSING -->
## Ownership and Licensing

Copyright (c) 2026 Patrick Brijraj. All rights reserved.

This repository is publicly visible for portfolio evaluation, personal
learning, recruitment review, academic discussion, and non-commercial

open-source licence**.

Copying, modification, redistribution, production deployment, organisational
use, incorporation into another security solution, consulting use, and any
other commercial use require prior written permission. Any use that generates
revenue, supports a paid service, reduces commercial costs, or creates another
financial benefit requires a separate written commercial licence.

The toolkit is intended only for lawful defensive assessment on Windows
systems the user is authorised to assess. See [`LICENSE`](LICENSE) for the
full terms. For permission or commercial licensing enquiries, contact
`pbrijraj@goalpostbrij.co.za`.

```text
PUBLIC VIEWING
      |
      +-- portfolio review
      +-- personal learning
      `-- non-commercial evaluation
      |
      v
COPY / MODIFY / DEPLOY / COMMERCIALISE?
      |
      +-- NO  -> remain within evaluation permission
      `-- YES -> prior written permission -> commercial licence
```

## Documentation map

- [Two-dimensional architecture and metafields](docs/Architecture-2D-Metafields.md)
- [Detailed architecture](docs/Architecture.md)
- [Script catalog](docs/Script-Catalog.md)
- [Usage guidance](docs/Usage.md)
- [Testing and quality assurance](docs/Testing.md)
- [Business value](docs/Business-Value.md)
- [Pre-publication checklist](PRE-PUBLISH-CHECKLIST.md)

## Visual assets

- Editable Mermaid source: `assets/diagrams/architecture.mmd`
- Screenshot guidance: `assets/screenshots/README.md`
