# Aedis SCA

GitHub Action that scans the checked-out repository with [Trivy](https://trivy.dev) and **fails the job when a
finding at or above the configured severity is not accepted**: known vulnerabilities of the dependencies in the lock
files, secrets committed in the files and misconfigurations in Dockerfiles, Kubernetes manifests, Helm charts and
IaC. Everything lands in one JSON summary (`aedis.platform/deps-summary/v2`) with a normalized severity, a Markdown
report in the job summary and the SARIF in code scanning, so one acceptance file and one gate cover the three
scanners. Acceptances live in the repository, each with an expiry date and, optionally, the paths it is limited to, so
a risk is never accepted silently or forever. Trivy is the release binary, pinned by version and SHA-256 in
`action.yml`, with its database cached between runs. Part of the
[Aedis Platform](https://github.com/aedis-build/aedis-platform), usable on its own.

## Usage

```yaml
jobs:
  sca:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # SARIF in code scanning; drop it (or sarif-upload: false) to keep the gate only
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: aedis-build/aedis-sca@<sha of the release tag> # vX.Y.Z
```

Pin the action by the commit SHA of a release tag with the tag in the comment, as above: Dependabot
(`package-ecosystem: github-actions`) then opens the repin pull request at every release, SHA and comment together.
Linux x64 runners only (`ubuntu-latest`).

### Inputs

| Input | Default | Meaning |
|---|---|---|
| `scanners` | `vuln,secret,misconfig` | Trivy scanners, comma-separated (`license` can be added) |
| `severity` | `HIGH,CRITICAL` | Severities of the vulnerabilities reported (Trivy names) |
| `config-severity` | `HIGH,CRITICAL` | Severities of the secrets and misconfigurations reported; separate from `severity` because `ignore-unfixed` never applies to them and a `MEDIUM` manifest check (an image tagged `latest`, say) would otherwise block every merge |
| `ignore-unfixed` | `true` | Leave out the vulnerabilities without a fixed version (vulnerabilities only) |
| `path` | `.` | Directory to scan |
| `accept-file` | `deps-accept.yaml` | Risk acceptance file (below); a missing file accepts nothing |
| `fail-on` | `High` | Lowest severity that fails the job, over the unaccepted findings: `High`, `Medium` or `Low` |
| `summary-name` | `deps-summary` | Artifact with `deps-summary.json`, `report.md`, `trivy.json` and `trivy.sarif` |
| `sarif-upload` | `true` | Upload the SARIF to code scanning (category `aedis-sca/trivy`); needs `security-events: write` on the job, otherwise the upload is skipped with a warning |

Output `result`: `pass` or `fail`.

## What it checks

One `trivy fs` run over `path` at the union of `severity` and `config-severity`, then `deps-summary.py` keeps the
vulnerabilities at `severity` and the secrets and misconfigurations at `config-severity`, applies the acceptances
and the gate, and writes the summary, the report and the SARIF (converted from the same JSON, so it carries the
union). Findings are normalized: `severity` is `high` (Trivy `CRITICAL` and `HIGH`), `medium`, `low` or `info`.

**Vulnerabilities** (`vuln`). Packages in the lock files Trivy understands (`pnpm-lock.yaml`, `package-lock.json`,
`yarn.lock`, `packages.lock.json`, `*.deps.json`, `go.sum`, `poetry.lock`, `Cargo.lock`, `Gemfile.lock`, Maven
and Gradle lock files, and more) against the Trivy database. `id` is the `CVE-` or `GHSA-` identifier, with
`package`, `installed`, `fixed` and `path` (the lock file). With `ignore-unfixed` only what has a fixed version
counts. .NET without a `packages.lock.json` is invisible to Trivy: the Aedis Platform `coverage.yml` adds
`dotnet list package --vulnerable` through the same script (below).

**Secrets** (`secret`). Credentials, keys and tokens in the files, by the Trivy secret rules. `id` is the rule
(`aws-access-key-id`, `github-pat`, `private-key`...), `path` the file and `line` where it starts; the matched value
never reaches the summary. A real leak is rotated, not accepted.

**Misconfigurations** (`misconfig`). Dockerfiles, Kubernetes manifests, Helm charts, Terraform, CloudFormation and
the other configuration formats Trivy checks. `id` is the `AVD-` identifier (`AVD-DS-0002`, `AVD-KSV-0017`...), with
`path` and `line`.

## Accepting a risk

`deps-accept.yaml` in the repository (or the file named in `accept-file`):

```yaml
accept:
  - id: CVE-2024-4068            # CVE-, GHSA-, AVD- or a Trivy secret rule id
    until: 2026-12-31            # required: past this date the finding blocks again and the summary warns
    reason: braces is only reached by the build tooling; ticket SEC-123
  - id: AVD-DS-0002
    until: 2026-12-31
    reason: the example images run as root on purpose
    paths: [examples/]           # optional: only findings whose path starts with one of these
  - package: braces              # the v1 form still works: every advisory of this package, whatever its id
    until: 2026-12-31
    reason: no reachable call path; re-evaluated at every upgrade
```

`test/run.sh` proves the rules on fixture reports (Trivy with a vulnerability, a secret and misconfigurations;
`dotnet list package`; `pnpm audit`), and `aedis-ci` also runs the action against this repository.

## Summary

`deps-summary.json` in the `deps-summary` artifact (`aedis.platform/deps-summary/v2`; readers of v1 keep `schema`,
`result`, `blocking` and `accepted`; `counts` keys are now lowercase and every finding has `tool` and `id`):

```json
{
  "schema": "aedis.platform/deps-summary/v2",
  "failOn": "High", "result": "fail",
  "counts": {"high": 3, "medium": 0, "low": 0, "info": 0}, "blocking": 2, "accepted": 1,
  "tools": {"trivy": {"ran": true, "findings": 3}, "dotnet": {"ran": false, "findings": 0}, "pnpm": {"ran": false, "findings": 0}},
  "warnings": ["acceptance CVE-2024-4068 expired on 2020-01-01: the finding blocks again"],
  "findings": [{"tool": "trivy", "id": "CVE-2024-4068", "severity": "high", "package": "braces", "installed": "3.0.2", "fixed": "3.0.3",
                "path": "pnpm-lock.yaml", "line": null, "title": "braces: fails to limit the number of characters it can handle",
                "url": "https://avd.aquasec.com/nvd/cve-2024-4068", "accepted": null}]
}
```

`deps-summary.py` is also the one source for the package audits of the Aedis Platform coverage workflows: it reads
the JSON of `trivy fs`, of `dotnet list package --vulnerable --include-transitive --format json` and of
`pnpm audit --json` by their shape, in any combination, and the same `deps-accept.yaml` covers all of them.

```bash
python3 .aedis-sca/deps-summary.py --input deps.json --accept deps-accept.yaml --out deps-summary.json
```

## Recipes

Stricter on a production service: `MEDIUM` vulnerabilities too, a `Medium` gate, and the summary read by a later
step.

```yaml
      - uses: aedis-build/aedis-sca@<sha of the release tag> # vX.Y.Z
        id: sca
        with:
          severity: MEDIUM,HIGH,CRITICAL
          fail-on: Medium
      - if: always() && steps.sca.outputs.result == 'fail'
        run: python3 -c "import json; s=json.load(open('sca/deps-summary.json')); print('\n'.join(f['id'] for f in s['findings'] if not f['accepted']))"
```

Only secrets and misconfigurations, on a repository whose dependencies are audited elsewhere:

```yaml
      - uses: aedis-build/aedis-sca@<sha of the release tag> # vX.Y.Z
        with:
          scanners: secret,misconfig
          config-severity: MEDIUM,HIGH,CRITICAL
```

Notifications and issues belong to the caller: one `curl` of `sca/deps-summary.json` to the webhook of your choice,
or `gh issue create` from the unaccepted findings, after the scan, with `if: always()`.

## License

Apache-2.0. See [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md).
