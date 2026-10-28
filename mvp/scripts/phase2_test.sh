#!/usr/bin/env bash
# Phase 2 deny-path matrix runner.
# Exercises every deny-path scenario per Alpha's attack-tree + the canonical §6 chain.
# Expected outcome per scenario is documented in the client.py scenario definitions.

set -u

cd "$(dirname "$0")/../test_client"
if [ ! -d venv ]; then
    python3 -m venv venv
    venv/bin/pip install -q -r requirements.txt
fi

export GATEWAY_URL="${GATEWAY_URL:-http://localhost:8444}"
export GATEWAY_TEST_MODE="synthetic"

scenarios=(
    "happy-path"
    "envelope-purpose-miss"
    "envelope-method-miss"
    "missing-dpop"
    "cnf-jkt-mismatch"
    "expired-token"
    "revoked-user-deny"
    "enumeration-sweep"
)

echo "==== IntentGuard Gateway MVP - Phase 2 Deny-Path Matrix ===="
echo "Gateway: $GATEWAY_URL"
echo

for s in "${scenarios[@]}"; do
    echo "-------- Scenario: $s --------"
    venv/bin/python client.py scenario "$s"
    echo
done

echo "==== Phase 2 test run complete ===="
echo "Review docker logs for OCSF ledger events per scenario:"
echo "  docker logs intentguard_gateway --tail 200"
