# Windows Security Hardening

Defensive Windows assessment, control verification, evidence, and recommendations.

## Two-dimensional metafield architecture

| Domain / Lifecycle | Discover | Assess | Explain | Verify |
|---|---|---|---|---|
| Remote access | X | X | X | X |
| Endpoint posture | X | X | X | X |
| Service integrity | X | X | X | X |
| Secure-site risk | X | X | X | X |
| System conflicts | X | X | X | X |

## Line map

```text
BUSINESS DRIVER
      |
      +--> PURPOSE ---------> Why the capability exists
      |
      +--> INPUT -----------> What evidence enters
      |
      +--> PROCESS ---------> How evidence is transformed
      |
      +--> CONTROL ---------> What limits behavior
      |
      +--> OUTPUT ----------> What is produced
      |
      +--> EVIDENCE --------> What supports a decision
      |
      +--> RISK ------------> What requires human review
      |
      +--> VALUE -----------> Why the result matters
```

## Component flow

```mermaid
flowchart LR
    A[Authorized Windows endpoint] --> B[Configuration collection]
    B --> C[Normalization]
    C --> D[Control evaluation]
    D --> E{Finding status}
    E -->|Pass| F[Evidence]
    E -->|Warning or fail| G[Recommendation]
    G --> H[Human review]
```

## Metafield dictionary

| Metafield | Meaning |
|---|---|
| Purpose | The problem or control objective addressed |
| Actor | The authorized person operating or reviewing the script |
| Input | Files, local configuration, services, events, or dependencies |
| Trigger | Manual execution in a controlled environment |
| Process | Collection, validation, analysis, conversion, or reporting |
| Decision | Pass, warning, fail, unknown, ready, or review required |
| Output | Console findings, structured objects, reports, or transformed files |
| Evidence | Observed values, status, rationale, and validation result |
| Control | Least privilege, assessment-first behavior, and explicit authorization |
| Risk | False positives, operational disruption, privacy, or environment assumptions |
| Recovery | Rollback or no-change behavior appropriate to the script |
| Boundary | Local and explicitly authorized systems only |
| Business value | Governance visibility, diagnostic clarity, automation, or repeatability |

## Governance-to-technology traceability

```text
Governance objective
        |
        v
Technical control intent
        |
        v
PowerShell collection or automation
        |
        v
Finding / output / evidence
        |
        v
Human decision and accountable action
```
