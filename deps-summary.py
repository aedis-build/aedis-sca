#!/usr/bin/env python3
"""Joins what Trivy (`trivy fs --format json`), `dotnet list package --vulnerable --include-transitive --format json`
and `pnpm audit --json` found into one summary, aedis.platform/deps-summary/v2, and applies the gate: any finding at
or above --fail-on that is not accepted fails.

Every --input file is read by its shape (SchemaVersion/Results: Trivy; projects: dotnet; advisories: pnpm). Findings
are normalized across tools: `tool` (trivy, dotnet, pnpm), `id` (CVE-/GHSA- for a package, the Trivy RuleID for a
secret, AVD- for a misconfiguration), `severity` high/medium/low/info (critical counts as high), `package`,
`installed`, `fixed`, `path` (lock file, project, Dockerfile, manifest or the file holding the secret), `line`,
`title`, `url`. Trivy vulnerabilities are kept at --vuln-severity and its secrets and misconfigurations at
--config-severity (Trivy names: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL); dotnet and pnpm report everything.

Acceptances (deps-accept.yaml) match by `id`, or by `package` (the v1 alias: every id of that package), with optional
`paths` (prefixes of the finding's path) and a required `until` (YYYY-MM-DD): an expired or dateless acceptance is
ignored and listed in `warnings`.

Usage: deps-summary.py --input FILE [FILE ...] [--accept deps-accept.yaml] [--fail-on High|Medium|Low]
         [--vuln-severity HIGH,CRITICAL] [--config-severity HIGH,CRITICAL] [--out deps-summary.json] [--markdown report.md]
       deps-summary.py --self-test
"""
import argparse, json, os, sys
from datetime import date, datetime, timezone

SCHEMA = "aedis.platform/deps-summary/v2"
SEV = {"critical": "high", "high": "high", "moderate": "medium", "medium": "medium", "low": "low", "info": "info"}
RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}
FAIL_ON = {"High": "high", "Medium": "medium", "Low": "low"}


def finding(tool, ident, severity, package="", installed="", fixed="", path="", line=None, title="", url=""):
    return {"tool": tool, "id": ident, "severity": SEV.get(str(severity or "").lower(), "info"), "package": package or "",
            "installed": installed or "", "fixed": fixed or "", "path": path or "", "line": line, "title": title or ident,
            "url": url or "", "accepted": None}


def sevset(names):
    return {n.strip().upper() for n in names.split(",") if n.strip()}


def trivy_findings(report, vuln_severity, config_severity):
    """Vulnerabilities at vuln_severity, secrets and misconfigurations at config_severity (Trivy names)."""
    out = []
    for r in report.get("Results") or []:
        target = r.get("Target", "")
        for v in r.get("Vulnerabilities") or []:
            if v.get("Severity", "UNKNOWN").upper() in vuln_severity:
                out.append(finding("trivy", v.get("VulnerabilityID"), v.get("Severity"), v.get("PkgName"), v.get("InstalledVersion"),
                                   v.get("FixedVersion"), target, None, v.get("Title"), v.get("PrimaryURL")))
        for s in r.get("Secrets") or []:
            if s.get("Severity", "UNKNOWN").upper() in config_severity:
                out.append(finding("trivy", s.get("RuleID"), s.get("Severity"), path=target, line=s.get("StartLine"), title=s.get("Title")))
        for m in r.get("Misconfigurations") or []:
            if m.get("Severity", "UNKNOWN").upper() in config_severity:
                out.append(finding("trivy", m.get("AVDID") or m.get("ID"), m.get("Severity"), path=target,
                                   line=(m.get("CauseMetadata") or {}).get("StartLine") or None, title=m.get("Title"), url=m.get("PrimaryURL")))
    return out


def dotnet_findings(report):
    """One finding per advisory, package and project (the same package under two frameworks is one finding)."""
    out, seen = [], set()
    for project in report.get("projects") or []:
        path = project.get("path", "")
        for fw in project.get("frameworks") or []:
            for kind in ("topLevelPackages", "transitivePackages"):
                for pkg in fw.get(kind) or []:
                    for v in pkg.get("vulnerabilities") or []:
                        url = v.get("advisoryurl") or ""
                        ident = url.rstrip("/").rsplit("/", 1)[-1] if url else f"dotnet:{pkg['id']}"
                        if (ident, pkg["id"], path) in seen:
                            continue
                        seen.add((ident, pkg["id"], path))
                        kind_label = "transitive" if kind == "transitivePackages" else "direct"
                        out.append(finding("dotnet", ident, v.get("severity"), pkg["id"], pkg.get("resolvedVersion"), "", path, None,
                                           f"{pkg['id']} ({kind_label})", url))
    return out


def pnpm_findings(report):
    if "error" in report:  # pnpm audit without an answer from the registry: no evidence, no pass
        raise SystemExit(f"pnpm audit failed: {report['error']}")
    out = []
    for adv in (report.get("advisories") or {}).values():
        versions = ", ".join(sorted({f["version"] for f in adv.get("findings") or [] if f.get("version")}))
        ident = adv.get("github_advisory_id") or next(iter(adv.get("cves") or []), None) or f"npm:{adv.get('id')}"
        out.append(finding("pnpm", ident, adv.get("severity"), adv.get("module_name"), versions, adv.get("patched_versions"),
                           "pnpm-lock.yaml", None, adv.get("title"), adv.get("url")))
    return out


def read_input(path):
    """(tool, report) of a JSON file, by its shape."""
    data = json.load(open(path, encoding="utf-8"))
    if "SchemaVersion" in data or "Results" in data:
        return "trivy", data
    if "projects" in data:
        return "dotnet", data
    if "advisories" in data or "error" in data:
        return "pnpm", data
    raise SystemExit(f"{path}: not a Trivy, dotnet list package or pnpm audit report")


def load_accepts(data, today):
    """(rules, warnings) from a deps-accept.yaml document."""
    rules, warnings = [], []
    for a in (data or {}).get("accept") or []:
        ident, package = a.get("id"), a.get("package")
        if not ident and not package:
            warnings.append("acceptance without id or package ignored"); continue
        label, until = ident or package, a.get("until")
        if not until:
            warnings.append(f"acceptance {label} without until ignored"); continue
        if date.fromisoformat(str(until)) < today:
            warnings.append(f"acceptance {label} expired on {until}: the finding blocks again"); continue
        rules.append({"id": ident, "package": package, "paths": a.get("paths") or [], "reason": a.get("reason") or "", "until": str(until)})
    return rules, warnings


def accepted_by(f, rules):
    for r in rules:
        if r["id"] and r["id"] != f["id"]:
            continue
        if r["package"] and r["package"].lower() != f["package"].lower():
            continue
        if r["paths"] and not any(f["path"].startswith(p) for p in r["paths"]):
            continue
        return r["reason"]
    return None


def summarize(inputs, accepts=(), fail_on="High", vuln_severity=frozenset({"HIGH", "CRITICAL"}),
              config_severity=frozenset({"HIGH", "CRITICAL"}), warnings=()):
    """inputs: [(tool, report)] as read_input returns them."""
    warnings, findings = list(warnings), []
    tools = {t: {"ran": False, "findings": 0} for t in ("trivy", "dotnet", "pnpm")}
    for tool, report in inputs:
        found = (trivy_findings(report, vuln_severity, config_severity) if tool == "trivy"
                 else dotnet_findings(report) if tool == "dotnet" else pnpm_findings(report))
        tools[tool]["ran"] = True; tools[tool]["findings"] += len(found); findings += found
    findings.sort(key=lambda f: (-RANK[f["severity"]], f["tool"], f["path"], f["id"]))
    for f in findings:
        f["accepted"] = accepted_by(f, accepts)
    threshold = RANK[FAIL_ON[fail_on]]
    blocking = [f for f in findings if RANK[f["severity"]] >= threshold and not f["accepted"]]
    return {"schema": SCHEMA, "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "failOn": fail_on,
            "result": "pass" if not blocking else "fail", "counts": {s: sum(1 for f in findings if f["severity"] == s) for s in RANK},
            "blocking": len(blocking), "accepted": sum(1 for f in findings if f["accepted"]), "tools": tools,
            "warnings": warnings, "findings": findings}


def cell(value):
    return str(value or "").replace("|", "\\|")


def markdown(s):
    """Report for the job summary: the result line, every finding and the warnings."""
    c = s["counts"]
    lines = [f"### SCA: {s['result']} ({c['high']} high, {c['medium']} medium, {c['low']} low, {c['info']} info; "
             f"{s['accepted']} accepted, {s['blocking']} blocking at or above {s['failOn']})", ""]
    if s["findings"]:
        lines += ["| Severity | Tool | Id | Package or title | Installed | Fixed | Path | Accepted |", "|---|---|---|---|---|---|---|---|"]
        for f in s["findings"]:
            ident = f"[{cell(f['id'])}]({f['url']})" if f["url"] else cell(f["id"])
            path = f"{f['path']}:{f['line']}" if f["line"] else f["path"]
            lines.append(f"| {f['severity']} | {f['tool']} | {ident} | {cell(f['package'] or f['title'])} | {cell(f['installed'])} | "
                         f"{cell(f['fixed'])} | {cell(path)} | {cell(f['accepted'])} |")
    lines += [f"- warning: {w}" for w in s["warnings"]]
    return "\n".join(lines) + "\n"


def self_test():
    today = date(2026, 6, 1)
    trivy = {"SchemaVersion": 2, "Results": [
        {"Target": "pnpm-lock.yaml", "Class": "lang-pkgs", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2024-4068", "PkgName": "braces", "InstalledVersion": "3.0.2", "FixedVersion": "3.0.3", "Severity": "HIGH", "Title": "ReDoS", "PrimaryURL": "u"},
            {"VulnerabilityID": "CVE-2024-0001", "PkgName": "x", "InstalledVersion": "1", "Severity": "MEDIUM"}]},
        {"Target": "config/app.env", "Class": "secret", "Secrets": [{"RuleID": "aws-access-key-id", "Severity": "CRITICAL", "Title": "AWS Access Key ID", "StartLine": 3}]},
        {"Target": "Dockerfile", "Class": "config", "Misconfigurations": [
            {"ID": "DS002", "AVDID": "AVD-DS-0002", "Severity": "HIGH", "Title": "root user", "PrimaryURL": "m", "CauseMetadata": {"StartLine": 0}},
            {"ID": "DS026", "AVDID": "AVD-DS-0026", "Severity": "MEDIUM", "Title": "no HEALTHCHECK"}]}]}
    s = summarize([("trivy", trivy)])
    assert s["result"] == "fail" and s["counts"] == {"high": 3, "medium": 0, "low": 0, "info": 0}, s["counts"]  # MEDIUM filtered on both sides
    assert [f["id"] for f in s["findings"]] == ["AVD-DS-0002", "aws-access-key-id", "CVE-2024-4068"]
    assert s["findings"][1]["line"] == 3 and s["findings"][0]["line"] is None and s["findings"][2]["fixed"] == "3.0.3"
    s = summarize([("trivy", trivy)], config_severity={"MEDIUM", "HIGH", "CRITICAL"})
    assert s["counts"]["medium"] == 1 and s["tools"]["trivy"] == {"ran": True, "findings": 4}
    assert summarize([("trivy", {"SchemaVersion": 2})])["result"] == "pass"
    # Acceptances: by id, by package (v1 alias), by path prefix; expired, dateless and empty are warnings.
    rules, warns = load_accepts({"accept": [
        {"id": "CVE-2024-4068", "until": "2999-01-01", "reason": "r"},
        {"id": "AVD-DS-0002", "until": "2999-01-01", "paths": ["examples/"], "reason": "scoped"},
        {"package": "Braces", "until": "2020-01-01", "reason": "old"},
        {"id": "x", "reason": "no date"}, {"until": "2999-01-01"}]}, today)
    assert len(rules) == 2 and len(warns) == 3 and "expired" in warns[0], warns
    s = summarize([("trivy", trivy)], rules)
    assert s["blocking"] == 2 and s["accepted"] == 1 and s["findings"][2]["accepted"] == "r", s
    # dotnet: the advisory id from the URL, direct and transitive, one finding for two frameworks.
    dotnet = {"projects": [{"path": "src/A/A.csproj", "frameworks": [
        {"framework": "net8.0", "topLevelPackages": [{"id": "Foo", "resolvedVersion": "1.0", "vulnerabilities": [{"severity": "High", "advisoryurl": "https://github.com/advisories/GHSA-1"}]}]},
        {"framework": "net10.0", "topLevelPackages": [{"id": "Foo", "resolvedVersion": "1.0", "vulnerabilities": [{"severity": "High", "advisoryurl": "https://github.com/advisories/GHSA-1"}]}],
         "transitivePackages": [{"id": "Bar", "resolvedVersion": "2.0", "vulnerabilities": [{"severity": "Low"}]}]}]}]}
    s = summarize([("dotnet", dotnet)])
    assert s["result"] == "fail" and s["counts"] == {"high": 1, "medium": 0, "low": 1, "info": 0} and s["findings"][0]["id"] == "GHSA-1"
    assert s["findings"][1]["id"] == "dotnet:Bar" and "transitive" in s["findings"][1]["title"]
    assert summarize([("dotnet", dotnet)], load_accepts({"accept": [{"package": "foo", "reason": "x", "until": "2999-01-01"}]}, today)[0])["result"] == "pass"
    assert summarize([("dotnet", {"projects": []})])["result"] == "pass"
    # pnpm: advisory id, patched versions, moderate is medium; an audit error never passes.
    npm = {"advisories": {"1": {"module_name": "braces", "severity": "high", "github_advisory_id": "GHSA-2", "url": "u", "patched_versions": ">=3.0.3",
                                "findings": [{"version": "3.0.2", "paths": [".>shadcn>fast-glob>braces"]}]},
                          "2": {"id": 9, "module_name": "next", "severity": "moderate", "cves": ["CVE-2025-1"], "findings": [{"version": "16.0.0", "paths": [".>next"]}]}}}
    s = summarize([("pnpm", npm)])
    assert s["result"] == "fail" and s["counts"]["high"] == 1 and s["counts"]["medium"] == 1 and s["findings"][0]["fixed"] == ">=3.0.3"
    assert [f["id"] for f in s["findings"]] == ["GHSA-2", "CVE-2025-1"]
    accept_ghsa = load_accepts({"accept": [{"id": "GHSA-2", "reason": "x", "until": "2999-01-01"}]}, today)[0]
    assert summarize([("pnpm", npm)], accept_ghsa)["result"] == "pass"
    assert summarize([("pnpm", npm)], accept_ghsa, fail_on="Medium")["result"] == "fail"
    assert summarize([("pnpm", {"advisories": {}, "metadata": {}})])["result"] == "pass"
    try:
        summarize([("pnpm", {"error": {"code": "ERR_PNPM_AUDIT_BAD_RESPONSE"}})]); raise AssertionError("an audit error cannot pass")
    except SystemExit:
        pass
    # Several inputs in one summary; the tools that did not run say so.
    s = summarize([("trivy", trivy), ("dotnet", dotnet), ("pnpm", npm)])
    assert s["blocking"] == 5 and s["tools"]["dotnet"]["findings"] == 2 and s["tools"]["pnpm"]["ran"]
    assert summarize([])["tools"]["trivy"] == {"ran": False, "findings": 0} and summarize([])["schema"] == SCHEMA
    md = markdown(s)
    assert "### SCA: fail (5 high" in md and "| high | trivy | [CVE-2024-4068](u) | braces | 3.0.2 | 3.0.3 | pnpm-lock.yaml |" in md and "config/app.env:3" in md
    print("self-test ok")


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--input", nargs="*", default=[])
    a.add_argument("--accept")
    a.add_argument("--fail-on", default="High", choices=list(FAIL_ON))
    a.add_argument("--vuln-severity", default="HIGH,CRITICAL")
    a.add_argument("--config-severity", default="HIGH,CRITICAL")
    a.add_argument("--out", default="deps-summary.json")
    a.add_argument("--markdown")
    a.add_argument("--self-test", action="store_true")
    args = a.parse_args()
    if args.self_test:
        self_test(); return 0
    accepts, warnings = [], []
    if args.accept and os.path.exists(args.accept):
        import yaml  # PyYAML ships with the runner
        accepts, warnings = load_accepts(yaml.safe_load(open(args.accept, encoding="utf-8")), date.today())
    s = summarize([read_input(p) for p in args.input], accepts, args.fail_on, sevset(args.vuln_severity), sevset(args.config_severity), warnings)
    json.dump(s, open(args.out, "w", encoding="utf-8"), indent=2)
    if args.markdown:
        open(args.markdown, "w", encoding="utf-8").write(markdown(s))
    c = s["counts"]
    print(f"SCA: {c['high']} high, {c['medium']} medium, {c['low']} low, {c['info']} info; {s['accepted']} accepted; "
          f"{s['blocking']} blocking (>= {args.fail_on})")
    for f in s["findings"]:
        if RANK[f["severity"]] >= RANK[FAIL_ON[args.fail_on]] and not f["accepted"]:
            print(f"  [{f['severity']}] {f['tool']} {f['id']} {f['package'] or f['title']} {f['installed']} {f['path']}")
    for w in s["warnings"]:
        print(f"::warning::{w}")
    return 1 if s["blocking"] else 0


if __name__ == "__main__":
    sys.exit(main())
