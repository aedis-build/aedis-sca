#!/usr/bin/env bash
# Tests of the summary and the gate without Trivy, dotnet or pnpm: the unit self-test, then the fixture reports
# (Trivy JSON with a vulnerability, a secret and misconfigurations; dotnet list package; pnpm audit) against the
# fixture acceptances. Needs python3 with PyYAML (the runner has it).
set -euo pipefail
cd "$(dirname "$0")/.."
out="$(mktemp -d)"
python3 deps-summary.py --self-test

# High gate over the three reports: CVE-2024-4068 blocks (expired acceptance), AVD-DS-0002 blocks (accepted only
# under examples/), AVD-KSV-0017 blocks (not accepted); the secret and Foo.Client are accepted; the MEDIUM
# vulnerability and the LOW misconfiguration are below the Trivy severities and never appear.
if python3 deps-summary.py --input test/trivy.json test/dotnet.json test/pnpm.json --accept test/deps-accept.yaml \
     --out "$out/high.json" --markdown "$out/high.md"; then
  echo "FAIL: expected the High gate to fail"; exit 1
fi
python3 - "$out/high.json" "$out/high.md" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert s["schema"] == "aedis.platform/deps-summary/v2" and s["result"] == "fail", s["result"]
assert s["counts"] == {"high": 5, "medium": 1, "low": 1, "info": 0}, s["counts"]
assert s["blocking"] == 3 and s["accepted"] == 2, (s["blocking"], s["accepted"])
blocking = sorted(f["id"] for f in s["findings"] if f["severity"] == "high" and not f["accepted"])
assert blocking == ["AVD-DS-0002", "AVD-KSV-0017", "CVE-2024-4068"], blocking
assert {f["tool"] for f in s["findings"]} == {"trivy", "dotnet", "pnpm"}
assert next(f for f in s["findings"] if f["id"] == "AVD-KSV-0017")["line"] == 18
assert s["tools"] == {"trivy": {"ran": True, "findings": 4}, "dotnet": {"ran": True, "findings": 2}, "pnpm": {"ran": True, "findings": 1}}, s["tools"]
assert any("expired" in w for w in s["warnings"]) and any("without until" in w for w in s["warnings"]), s["warnings"]
md = open(sys.argv[2]).read()
assert md.startswith("### SCA: fail (5 high, 1 medium, 1 low, 0 info; 2 accepted, 3 blocking at or above High)") and "| config/app.env:3 |" in md, md
PY

# Wider Trivy severities: the MEDIUM vulnerability and the LOW misconfiguration show up, and a Low gate blocks them.
python3 deps-summary.py --input test/trivy.json --vuln-severity MEDIUM,HIGH,CRITICAL --config-severity LOW,MEDIUM,HIGH,CRITICAL \
  --accept /nonexistent.yaml --out "$out/wide.json" || true
python3 -c "import json,sys; s=json.load(open(sys.argv[1])); assert s['counts']=={'high':4,'medium':1,'low':1,'info':0} and s['accepted']==0, s['counts']" "$out/wide.json"
if python3 deps-summary.py --input test/trivy.json --config-severity LOW,HIGH,CRITICAL --fail-on Low --out "$out/low.json" --accept test/deps-accept.yaml; then
  echo "FAIL: expected the Low gate to fail"; exit 1
fi
python3 -c "import json,sys; s=json.load(open(sys.argv[1])); assert s['blocking']==4 and s['counts']['low']==1, s" "$out/low.json"

# pnpm alone: moderate passes a High gate and fails a Medium one; the v1 call shape (one --input, --accept) still works.
python3 deps-summary.py --input test/pnpm.json --accept test/deps-accept.yaml --out "$out/pnpm.json"
python3 -c "import json,sys; s=json.load(open(sys.argv[1])); assert s['result']=='pass' and s['tools']['trivy']['ran'] is False, s" "$out/pnpm.json"
if python3 deps-summary.py --input test/pnpm.json --fail-on Medium --out "$out/pnpm-medium.json"; then
  echo "FAIL: expected the Medium gate to fail"; exit 1
fi
echo "fixture tests ok"
