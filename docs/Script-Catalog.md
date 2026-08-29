# Script Catalog

## Analyze-RemoteAccessPolicy.ps1

**Purpose:** Identifies Windows settings and services that can influence remote access.

**Metafields:**
- Input: Remote-access service and policy state
- Process: Discovery and classification
- Output: Findings requiring review
- Risk: Environment-specific false positives

## Analyze-SystemRisk-ForSecureSites.ps1

**Purpose:** Reviews selected platform and transport-security conditions that can affect access to secure sites.

**Metafields:**
- Input: TLS, browser, network, and system configuration
- Process: Risk-oriented assessment
- Output: Diagnostic observations
- Risk: Results may vary by organizational architecture

## MicrosoftServiceMasquerading.ps1

**Purpose:** Reviews service information for indicators that require validation.

**Metafields:**
- Input: Installed Windows service metadata
- Process: Pattern and path review
- Output: Candidate findings
- Risk: A finding is not proof of compromise

## SecurityPosture_Report.ps1

**Purpose:** Produces a point-in-time endpoint security posture report.

**Metafields:**
- Input: Services, registry, firewall, and network information
- Process: Baseline-oriented assessment
- Output: Status-oriented report
- Risk: Baseline assumptions must be verified

## Verify-RemoteAccessLockdown_WithRecommendations.ps1

**Purpose:** Verifies remote-access controls and provides recommendations where controls differ from the intended state.

**Metafields:**
- Input: Remote-control configuration
- Process: Compare and explain
- Output: Status and recommendation
- Risk: Recommendations require architectural review

## WindowsSecurityReview.ps1

**Purpose:** Reviews selected Windows security capabilities and configuration.

**Metafields:**
- Input: Endpoint security settings
- Process: Structured review
- Output: Findings and evidence
- Risk: Hardware or edition limitations may apply

## WindowsSystemConflictIntegrityReview.ps1

**Purpose:** Reviews configuration conflicts that can affect system integrity or security tooling.

**Metafields:**
- Input: Security-product and platform state
- Process: Conflict analysis
- Output: Review findings
- Risk: Correlation does not prove causation
