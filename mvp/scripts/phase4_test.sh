#!/usr/bin/env bash
# Phase 4 closed-loop test:
#   Directly answers Alpha's A2 attack-tree finding.
#   Enumeration inside an admitted purpose ("read-invoices") is admitted
#   by the structural gate at step 4 — by design. Phase 4 catches it in
#   aggregate: BDD counts admits per subject, trips at threshold, proposes
#   revocation to Sidecar, Sidecar auto-approves and calls the gateway's
#   /_admin/revoke, and subsequent requests from that subject die at step 5.
set -euo pipefail

SENTINEL="http://localhost:8091"
GATEWAY="http://localhost:8444"
BDD="http://localhost:8092"
SIDECAR="http://localhost:8093"

echo "==== Phase 4 test ===="
echo "step 0: reset all state"
curl -s -X POST "$SENTINEL/_received/reset" > /dev/null
curl -s -X POST "$BDD/_reset" > /dev/null
curl -s -X POST "$SIDECAR/_reset" > /dev/null

# Reset gateway negation store by dropping alice/eve from it if already there.
# Easiest reset: docker compose restart gateway. Non-destructive if state
# is only in-memory. Skipping for speed; test uses a fresh subject 'eve'
# who wasn't in the compose REVOKED_SUBjects env (that pre-loads dave).
FRESH_SUBJECT="alice@ibae.lab"
# Confirm alice is NOT pre-revoked from prior runs.
STORE_BEFORE="$(curl -s "$GATEWAY/_admin/negation_store")"
echo "  negation store before: $STORE_BEFORE"
if echo "$STORE_BEFORE" | grep -q "$FRESH_SUBJECT"; then
  echo "  alice already revoked from prior run; restarting gateway to clear"
  docker restart intentguard_gateway > /dev/null
  sleep 3
  curl -s -X POST "$BDD/_reset" > /dev/null
  curl -s -X POST "$SIDECAR/_reset" > /dev/null
fi

echo "step 1: run enumeration sweep as alice (20 requests to /invoices/1..20)"
cd "$(dirname "$0")/.."
GATEWAY_URL="${GATEWAY_URL:-http://localhost:8444}" GATEWAY_TEST_MODE=synthetic test_client/venv/bin/python test_client/client.py scenario enumeration-sweep 2>&1 | \
  awk '/-> [0-9]+/ {print}' | tail -25

echo "step 2: give BDD -> Sidecar -> gateway loop a moment to settle"
sleep 2

echo "step 3: check BDD status"
curl -s "$BDD/_status" | python3 -m json.tool

echo "step 4: check Sidecar decisions"
curl -s "$SIDECAR/_queue" | python3 -m json.tool

echo "step 5: check gateway negation store"
STORE_AFTER="$(curl -s "$GATEWAY/_admin/negation_store")"
echo "  negation store after: $STORE_AFTER"

echo "step 6: assertions"
python3 - <<'PY'
import json, urllib.request

bdd = json.loads(urllib.request.urlopen("http://localhost:8092/_status").read())
sidecar = json.loads(urllib.request.urlopen("http://localhost:8093/_queue").read())
store = json.loads(urllib.request.urlopen("http://localhost:8444/_admin/negation_store").read())

fails = []
if bdd["proposals_sent"] < 1:
    fails.append(f"BDD sent no proposals (events_seen={bdd['events_seen']})")
if "alice@ibae.lab" not in bdd.get("already_proposed", []):
    fails.append(f"BDD didn't flag alice (already_proposed={bdd.get('already_proposed')})")
if not any(d["decision"] == "approved" for d in sidecar.get("decided", [])):
    fails.append("Sidecar never approved a proposal")
if "alice@ibae.lab" not in store.get("revoked_subjects", []):
    fails.append(f"Gateway didn't revoke alice (revoked_subjects={store.get('revoked_subjects')})")

if fails:
    for f in fails:
        print(f"FAIL: {f}")
    raise SystemExit(1)
print("OK: BDD flagged, Sidecar approved, gateway revoked - closed loop works")
PY

echo "step 7: prove the revocation stops in-flight abuse"
echo "  send one more request as alice; expect 403 with deny at step5_gust"
NEW_REQ="$(GATEWAY_URL="${GATEWAY_URL:-http://localhost:8444}" GATEWAY_TEST_MODE=synthetic test_client/venv/bin/python test_client/client.py scenario happy-path 2>&1 | grep -E -- '-> [0-9]+' | tail -1)"
echo "  $NEW_REQ"
if echo "$NEW_REQ" | grep -q -- "-> 403"; then
  echo "OK: post-revocation request denied (403)"
else
  echo "FAIL: post-revocation request not denied"
  exit 1
fi

echo "==== Phase 4 verified: enumeration abuse detected + revoked in-band ===="
