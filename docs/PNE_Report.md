# Protection Needs Evaluation (PNE) Report

## 1. System Assets

The Secure FastAPI JWT Auth REST API contains several critical assets that require explicit protection controls. The first asset is the relational database (SQLite in this lab implementation), which stores user identity records, password hashes, item ownership mappings, and item content. Even though SQLite is selected for development simplicity, the data has real confidentiality and integrity requirements because unauthorized alteration of ownership or user records would directly break trust boundaries in the application.

A second asset category is token material, specifically JWT access tokens and refresh tokens. Access tokens are bearer credentials that provide authorization to protected resources, while refresh tokens allow a session to be prolonged without password re-entry. Exposure of either token can lead to account takeover risk, lateral privilege abuse, or persistent unauthorized sessions.

A third asset category is API endpoints and associated business logic. Public endpoints such as registration and login are attractive entry points for brute-force and abuse. Authenticated endpoints are sensitive because they process object references and user data. The item endpoints are especially relevant for object-level authorization defects such as Insecure Direct Object Reference (IDOR), where a valid user could attempt to read or modify records they do not own.

The fourth asset category is user data in transit and at rest, including usernames, emails, and user-generated item content. Even with minimal data fields, compromise can result in privacy violations, phishing vectors, and reputational damage. Security posture therefore must not rely only on authentication, but must include robust authorization and defensive HTTP controls.

## 2. Threat Sources

Threats originate from multiple actor classes. External unauthenticated attackers can probe public endpoints, attempt credential stuffing, test weak session controls, and automate fuzzing to discover insecure states. They also may run automated scanners that exploit missing response headers, insecure cookies, or error disclosures.

Authenticated but malicious users are a high-priority threat source because they possess valid credentials and can legitimately reach protected routes. Their common abuse path is horizontal privilege escalation, often by manipulating path parameters such as item IDs. If ownership checks are missing or inconsistent, these attackers can read or alter other users' records without elevating role permissions.

Insider threats include developers, operators, or teammates with repository or runtime access. Insider risk includes accidental secret leakage, insecure debugging defaults, and intentionally weakened controls for convenience. In a CI/CD context, supply-chain and pipeline misconfiguration risks are also relevant if scanning gates are not mandatory.

Automated tooling itself can act as a stress threat source. Continuous scanners such as DAST tools may discover latent defects if hardening is incomplete. This risk source is beneficial when integrated in pipeline controls because it shifts defect detection earlier.

## 3. Protection Needs (Confidentiality / Integrity / Availability)

For the database asset, confidentiality is high because user identifiers and relational ownership data should be unavailable to unauthorized parties. Integrity is high because ownership tampering would invalidate authorization decisions and allow fraudulent data operations. Availability is medium to high for lab context: outage blocks grading and functional verification, but impact is lower than in mission-critical systems.

For JWT and refresh token assets, confidentiality is very high. These credentials are equivalent to session authority, and leakage immediately weakens account security. Integrity is high because forged or tampered tokens can bypass controls if validation is incomplete. Availability is medium because temporary token service interruption degrades user experience but does not inherently corrupt data.

For API endpoint logic, confidentiality and integrity are high. Endpoints enforce the policy boundary between users and data, so broken authorization has direct exploit value. Availability is high from an operations perspective because endpoint unavailability blocks all user workflows.

For user data assets, confidentiality is high due to privacy obligations, integrity is high due to trust and correctness requirements, and availability is medium in this educational deployment.

## 4. Security Requirements Derived from PNE

From these protection needs, mandatory controls are derived and implemented. First, object-level authorization must be enforced for all item-by-ID operations by validating that the requesting principal owns the resource before returning or mutating it. This directly mitigates IDOR and horizontal privilege escalation.

Second, session and credential handling must be hardened. Passwords must be stored only as bcrypt hashes with a strong work factor. Access tokens must be short lived, refresh tokens limited and validated, and signing secrets loaded from environment variables rather than source code.

Third, CSRF protection is required for all state-changing requests. The implementation must enforce a token check with signed cookie binding and reject mismatches with HTTP 403. This prevents cross-site request forgery against authenticated sessions.

Fourth, clickjacking and browser hardening headers must be universally applied. Denying framing with X-Frame-Options and CSP frame-ancestors protects UI embedding abuse, while additional headers reduce MIME confusion, tighten referral leakage, and constrain browser feature access.

Fifth, continuous verification must be policy-enforced in CI/CD with linting, tests, SAST, and DAST gates. Pipeline failure on high/critical findings ensures security regressions cannot silently pass into protected branches. Together, these controls map directly to confidentiality, integrity, and availability requirements identified by this PNE.
