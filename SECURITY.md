# Security policy

## Supported versions

One major at a time: the current one (`v1`). The previous major receives fixes until the first minor of the new one.
Callers pin the commit SHA of a release tag (`@<sha> # vX.Y.Z`), never a branch or a moving tag.

## Reporting a vulnerability

Use **Report a vulnerability** in this repository's Security tab (GitHub Private Vulnerability Reporting). Do not open a public issue for vulnerabilities.

- Acknowledgement within 3 business days.
- Initial severity assessment (CVSS) within 7 days.
- Fix or documented mitigation for high/critical severity within 30 days.
- Credit to the reporter in the advisory, if desired.

## Scope

`action.yml` and `deps-summary.py`: what runs in the caller's job, the Trivy release binary it pins by version and SHA-256, the reports it reads and the gate it applies. Trivy itself is covered by [aquasecurity/trivy](https://github.com/aquasecurity/trivy/security/policy); the Aedis Platform reusable workflows this repository calls by [aedis-build/aedis-platform](https://github.com/aedis-build/aedis-platform/security/policy).

## Practices of this repository

- Every action pinned by commit SHA and the scanner binary by version and checksum; `permissions: {}` by default; the action needs no credential (the SARIF upload uses the job's own token, when the job grants `security-events: write`).
- Dependencies updated by Dependabot; OpenSSF Scorecard published; releases immutable and attested by GitHub.
