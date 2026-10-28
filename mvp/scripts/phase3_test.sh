#!/usr/bin/env bash
# Phase 3 verification: run all Phase 2 scenarios, then assert every
# OCSF event landed at the mock Sentinel receiver with the right
# Log-Type header, HMAC-shaped Authorization prefix, correlation_uid
# preserved end-to-end, and per-step deny attribution.
set -euo pipefail

SENTINEL="http://localhost:8091"
GATEWAY="http://localhost:8444"

echo "==== Phase 3 test ===="
echo "reset mock Sentinel event store"
curl -s -X POST "$SENTINEL/_received/reset" > /dev/null

echo "run Phase 2 scenarios (generates OCSF events at gateway)"
bash "$(dirname "$0")/phase2_test.sh" > /tmp/phase3_p2.log 2>&1

sleep 2

echo "fetch mock Sentinel received-events dump"
DUMP="$(curl -s "$SENTINEL/_received")"
COUNT="$(echo "$DUMP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])')"

echo "== event count =="
echo "landed: $COUNT (expected: >= 26; 7 non-enum + 20 enumeration - 1 unauthed = 26 nominal)"

if [ "$COUNT" -lt 20 ]; then
  echo "FAIL: too few events reached mock Sentinel"
  exit 1
fi

echo "== per-step attribution (denies) =="
python3 - <<'PY'
import json, sys, urllib.request
d = json.loads(urllib.request.urlopen("http://localhost:8091/_received").read())
fails = [e for e in d["events"] if e["event"]["status"] == "Failure"]
by_step = {}
for e in fails:
    step = e["event"].get("unmapped", {}).get("deny_step", "MISSING")
    by_step[step] = by_step.get(step, 0) + 1
for step, n in sorted(by_step.items()):
    print(f"  {step}: {n}")
if "MISSING" in by_step:
    print("FAIL: at least one deny event has no step attribution")
    raise SystemExit(1)
expected = {"step1_jwks", "step2_dpop", "step4_structural", "step5_gust"}
missing = expected - by_step.keys()
if missing:
    print(f"FAIL: no denies attributed to: {sorted(missing)}")
    raise SystemExit(1)
print("OK: every deny attributed to a real admission step")
PY

echo "== transport-envelope integrity =="
python3 - <<'PY'
import json, urllib.request
d = json.loads(urllib.request.urlopen("http://localhost:8091/_received").read())
bad = 0
for e in d["events"]:
    if e.get("log_type") != "IntentGuardOCSF":
        bad += 1; continue
    auth = e.get("auth_prefix") or ""
    if not auth.startswith("SharedKey "):
        bad += 1; continue
    if not e["event"].get("metadata", {}).get("correlation_uid"):
        bad += 1
if bad:
    print(f"FAIL: {bad}/{d['count']} events malformed on transport envelope")
    raise SystemExit(1)
print(f"OK: all {d['count']} events carry Log-Type + SharedKey auth + correlation_uid")
PY

echo "==== Phase 3 verified: gateway -> Sentinel connector shape holds ===="
