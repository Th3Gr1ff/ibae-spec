#!/usr/bin/env python3
"""IntentGuard API Demo - "Compromise no longer grants carte blanche."

Demonstrates purpose-bound API access control. A service account with
"read-invoices" purpose can read invoices but cannot touch users, delete
records, or access admin config, even with valid credentials.

Usage:
    # Terminal 1: start all three services
    python demo.py serve

    # Terminal 2: run the demo scenarios
    python demo.py run
"""

import base64
import hashlib
import json
import os
import sys
import time
import uuid
import subprocess
import signal as signal_mod

import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import jwt


ISSUER_URL = "http://127.0.0.1:8710"
GATEWAY_URL = "http://127.0.0.1:8730"

BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
DIM = "\033[2m"


class EphemeralKey:
    def __init__(self):
        self._priv = ec.generate_private_key(ec.SECP256R1())

    @property
    def private_key(self):
        return self._priv

    @property
    def public_jwk(self) -> dict:
        numbers = self._priv.public_key().public_numbers()
        return {
            "kty": "EC", "crv": "P-256",
            "x": _b64url_int(numbers.x, 32),
            "y": _b64url_int(numbers.y, 32),
        }

    def jwk_thumbprint(self) -> str:
        jwk = self.public_jwk
        canonical = json.dumps(
            {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
            separators=(",", ":"),
        ).encode()
        return base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()


def _b64url_int(n: int, byte_length: int) -> str:
    b = n.to_bytes(byte_length, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def mint_token(identity: str, role: str, purpose: str, key: EphemeralKey) -> str:
    resp = requests.post(f"{ISSUER_URL}/mint", json={
        "identity": identity,
        "role": role,
        "purpose": purpose,
        "exp_seconds": 300,
        "cnf_jkt": key.jwk_thumbprint(),
    })
    resp.raise_for_status()
    return resp.json()["access_token"]


def build_dpop_proof(key: EphemeralKey, method: str, url: str) -> str:
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": key.public_jwk}
    payload = {
        "jti": uuid.uuid4().hex,
        "htm": method.upper(),
        "htu": url,
        "iat": int(time.time()),
    }
    priv_pem = key.private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return jwt.encode(payload, priv_pem, algorithm="ES256", headers=header)


def api_call(method: str, path: str, token: str, key: EphemeralKey, label: str) -> dict:
    url = f"{GATEWAY_URL}{path}"
    dpop = build_dpop_proof(key, method, url)
    headers = {"Authorization": f"Bearer {token}", "DPoP": dpop}
    resp = requests.request(method, url, headers=headers)
    return {"status": resp.status_code, "body": resp.json(), "label": label}


def print_result(result: dict, expect_success: bool):
    status = result["status"]
    label = result["label"]
    if expect_success and status < 400:
        print(f"  {GREEN}ADMITTED{RESET} [{status}] {label}")
        if "invoices" in result["body"]:
            for inv in result["body"]["invoices"][:2]:
                print(f"    {DIM}{inv['id']}: {inv['vendor']} ${inv['amount']}{RESET}")
    elif not expect_success and status >= 400:
        body = result["body"]
        reason = body.get("error", body.get("reason", "denied"))
        print(f"  {RED}BLOCKED{RESET}  [{status}] {label}")
        print(f"    {YELLOW}{reason}{RESET}")
    elif expect_success and status >= 400:
        print(f"  {RED}UNEXPECTED DENY{RESET} [{status}] {label}")
    else:
        print(f"  {YELLOW}UNEXPECTED ADMIT{RESET} [{status}] {label}")


def run_demo():
    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}IntentGuard API Demo{RESET}")
    print(f"{CYAN}\"Compromise no longer grants carte blanche.\"{RESET}")
    print(f"{'='*70}\n")

    key = EphemeralKey()

    print(f"{BOLD}SCENARIO 1: Legitimate service account{RESET}")
    print(f"{DIM}Invoice processing service with 'read-invoices' purpose{RESET}\n")
    token = mint_token("svc-invoice-reader", "finance-readonly", "read-invoices", key)
    print(f"  Purpose token minted: read-invoices")
    print(f"  Identity: svc-invoice-reader / finance-readonly\n")

    r = api_call("GET", "/api/invoices", token, key, "GET /api/invoices")
    print_result(r, expect_success=True)

    r = api_call("GET", "/api/invoices/INV-001", token, key, "GET /api/invoices/INV-001")
    print_result(r, expect_success=True)

    print(f"\n{BOLD}SCENARIO 2: Credential stolen, attacker pivots{RESET}")
    print(f"{DIM}Same valid token, attacker tries to reach beyond invoice reading{RESET}\n")
    print(f"  {YELLOW}Attacker has the same valid credentials.{RESET}")
    print(f"  {YELLOW}Token signature is valid. DPoP proof is valid.{RESET}")
    print(f"  {YELLOW}But the PURPOSE says 'read-invoices'...{RESET}\n")

    r = api_call("DELETE", "/api/invoices/INV-001", token, key,
                 "DELETE /api/invoices/INV-001 (destroy evidence)")
    print_result(r, expect_success=False)

    r = api_call("GET", "/api/users", token, key,
                 "GET /api/users (enumerate accounts)")
    print_result(r, expect_success=False)

    r = api_call("POST", "/api/users", token, key,
                 "POST /api/users (create backdoor account)")
    print_result(r, expect_success=False)

    r = api_call("POST", "/api/admin/config", token, key,
                 "POST /api/admin/config (change system config)")
    print_result(r, expect_success=False)

    print(f"\n{BOLD}SCENARIO 3: Different purpose, different access{RESET}")
    print(f"{DIM}User admin service with 'manage-users' purpose{RESET}\n")
    key2 = EphemeralKey()
    token2 = mint_token("svc-user-admin", "hr-ops", "manage-users", key2)
    print(f"  Purpose token minted: manage-users")
    print(f"  Identity: svc-user-admin / hr-ops\n")

    r = api_call("GET", "/api/users", token2, key2, "GET /api/users")
    print_result(r, expect_success=True)

    r = api_call("POST", "/api/users", token2, key2, "POST /api/users (create user)")
    print_result(r, expect_success=True)

    r = api_call("GET", "/api/invoices", token2, key2,
                 "GET /api/invoices (scope creep into finance)")
    print_result(r, expect_success=False)

    r = api_call("POST", "/api/admin/config", token2, key2,
                 "POST /api/admin/config (escalate to admin)")
    print_result(r, expect_success=False)

    print(f"\n{'='*70}")
    print(f"{BOLD}Result:{RESET} Valid credentials + valid signatures + valid session")
    print(f"        = access ONLY within the declared purpose.")
    print(f"        Compromise no longer grants carte blanche.")
    print(f"{'='*70}\n")


def serve():
    """Start all three services in subprocesses."""
    base = os.path.dirname(os.path.abspath(__file__))
    procs = []
    try:
        print(f"{BOLD}Starting IntentGuard API demo services...{RESET}\n")
        p1 = subprocess.Popen(
            [sys.executable, os.path.join(base, "issuer.py")],
            env={**os.environ, "ISSUER_PORT": "8710"},
        )
        procs.append(("Purpose Issuer [:8710]", p1))
        print(f"  {GREEN}Started{RESET} Purpose Issuer on :8710")

        p2 = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "demo_api:app",
             "--host", "127.0.0.1", "--port", "8720", "--log-level", "warning"],
            cwd=base,
        )
        procs.append(("Demo API [:8720]", p2))
        print(f"  {GREEN}Started{RESET} Demo API on :8720")

        p3 = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "gateway:app",
             "--host", "127.0.0.1", "--port", "8730", "--log-level", "warning"],
            cwd=base,
        )
        procs.append(("IntentGuard Gateway [:8730]", p3))
        print(f"  {GREEN}Started{RESET} IntentGuard Gateway on :8730")

        print(f"\n  {CYAN}All services running. Run 'python demo.py run' in another terminal.{RESET}")
        print(f"  {DIM}Press Ctrl+C to stop.{RESET}\n")

        for _, p in procs:
            p.wait()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Shutting down...{RESET}")
        for name, p in procs:
            p.terminate()
        for name, p in procs:
            p.wait()
        print(f"{GREEN}All services stopped.{RESET}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python demo.py [serve|run]")
        print("  serve - start all three services")
        print("  run   - run the demo scenarios (services must be running)")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "serve":
        serve()
    elif cmd == "run":
        run_demo()
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
