"""
Test client: signs DPoP proofs, acquires access tokens from AD FS
via client_credentials, and hits the gateway with the token + DPoP.

Phase 2 usage:
  python client.py health
  python client.py jwks
  python client.py persona <name> <METHOD> <path>
    where <name> is one of:
      invoice-reader   role=IBAE-ReadInvoices,     purpose=read-invoices
      ticket-reader    role=IBAE-ReadOwnTickets,  purpose=read-own-ticket
      admin            role=IBAE-Admin,            purpose=admin-full
      revoked-user     role=IBAE-ReadInvoices,    purpose=read-invoices  (dave-revoked, expected step-5 deny)

  python client.py scenario <name>
    Scenarios exercise a specific deny-path:
      happy-path              invoice-reader GET /invoices/1 -> 200
      envelope-purpose-miss   ticket-reader  GET /invoices/1 -> 403 at step 4
      envelope-method-miss    invoice-reader POST /invoices/1 -> 403 at step 4
      missing-dpop            invoice-reader GET /invoices/1 without DPoP header -> 401
      cnf-jkt-mismatch        invoice-reader GET /invoices/1 with mismatched keypair -> 401
      expired-token           invoice-reader GET /invoices/1 with 60s-past-expiry token -> 401
      revoked-user-deny       revoked-user GET /invoices/1 -> 403 at step 5
      enumeration-sweep       invoice-reader GET /invoices/{1..100} -> all 200 (A2 correct-by-design)

Real-AD-FS integration lands once the AD FS Purpose Issuer plugin
(task #51) exists. For now, GATEWAY_TEST_MODE=synthetic uses
locally-signed tokens with the synthetic key that the gateway loads
alongside AD FS JWKS.
"""
import base64
import hashlib
import json
import os
import sys
import time
import uuid

import httpx
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import jwt


GATEWAY_URL = os.environ.get("GATEWAY_URL", "https://localhost:8443")
ADFS_TOKEN_URL = os.environ.get(
    "ADFS_TOKEN_URL",
    "https://fs.ibae.lab/adfs/oauth2/token",
)
CLIENT_ID = os.environ.get("ADFS_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("ADFS_CLIENT_SECRET", "")
RESOURCE = os.environ.get("ADFS_RESOURCE", "urn:ibae:test:api")


def gen_dpop_key():
    """Ephemeral EC P-256 keypair for DPoP proof-of-possession."""
    return ec.generate_private_key(ec.SECP256R1())


def jwk_from_public_ec(pubkey):
    numbers = pubkey.public_numbers()
    def b64u(n, length):
        return base64.urlsafe_b64encode(
            n.to_bytes(length, "big")
        ).rstrip(b"=").decode()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u(numbers.x, 32),
        "y": b64u(numbers.y, 32),
    }


def jwk_thumbprint(jwk):
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"), sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def make_dpop_proof(private_key, method: str, url: str) -> str:
    jwk = jwk_from_public_ec(private_key.public_key())
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    payload = {
        "jti": str(uuid.uuid4()),
        "htm": method.upper(),
        "htu": url,
        "iat": int(time.time()),
    }
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(payload, priv_pem, algorithm="ES256", headers=header)


SYNTHETIC_JWKS_DIR = os.environ.get(
    "SYNTHETIC_JWKS_DIR",
    "/home/kenna/projects/ibae/mvp/synthetic_jwks",
)


def _ensure_synthetic_signing_key():
    """
    Persistent synthetic key across runs, so the JWKS file the gateway mounts
    stays stable. Generates the key + writes public JWK on first invocation.
    """
    os.makedirs(SYNTHETIC_JWKS_DIR, exist_ok=True)
    priv_path = os.path.join(SYNTHETIC_JWKS_DIR, "synthetic_signing_key.pem")
    jwks_path = os.path.join(SYNTHETIC_JWKS_DIR, "synthetic_jwks.json")

    from cryptography.hazmat.primitives.asymmetric import rsa
    if not os.path.exists(priv_path):
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(priv_path, "wb") as f:
            f.write(rsa_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        # Build public JWK for the gateway.
        pub = rsa_key.public_key().public_numbers()
        def b64u(n):
            length = (n.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(
                n.to_bytes(length, "big")
            ).rstrip(b"=").decode()
        jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "synthetic-scaffold",
            "n": b64u(pub.n),
            "e": b64u(pub.e),
        }
        with open(jwks_path, "w") as f:
            json.dump({"keys": [jwk]}, f)

    with open(priv_path, "rb") as f:
        return f.read()


# Persona catalog: sub / role / purpose triples used by scenarios.
PERSONAS: dict[str, dict[str, str]] = {
    "invoice-reader": {
        "sub": "alice@ibae.lab",
        "role": "IBAE-ReadInvoices",
        "purpose": "read-invoices",
    },
    "ticket-reader": {
        "sub": "bob@ibae.lab",
        "role": "IBAE-ReadOwnTickets",
        "purpose": "read-own-ticket",
    },
    "admin": {
        "sub": "carol@ibae.lab",
        "role": "IBAE-Admin",
        "purpose": "admin-full",
    },
    "revoked-user": {
        "sub": "dave@ibae.lab",
        "role": "IBAE-ReadInvoices",
        "purpose": "read-invoices",
    },
}


def synthetic_token(
    persona: str,
    dpop_jkt: str,
    exp_offset: int = 60,
) -> tuple[str, str]:
    """
    Phase-2 scaffold: generate a self-signed token for a named persona.
    Returns (token, signing_kid_note).

    exp_offset: seconds until expiry. Negative values produce
    an already-expired token for the expired-token deny-path test.

    The gateway loads our synthetic public JWK via mounted volume,
    so its step-1 JWKS validation recognizes the signature.

    Real AD-FS-tied testing requires the AD FS plugin from task #51.
    """
    if persona not in PERSONAS:
        raise KeyError(f"unknown persona: {persona}")
    p = PERSONAS[persona]
    priv_pem = _ensure_synthetic_signing_key()
    claims = {
        "sub": p["sub"],
        "role": p["role"],
        "purpose": p["purpose"],
        "provenance": "test-client-synthetic",
        "exp": int(time.time()) + exp_offset,
        "iat": int(time.time()),
        "cnf": {"jkt": dpop_jkt},
    }
    token = jwt.encode(
        claims, priv_pem, algorithm="RS256",
        headers={"kid": "synthetic-scaffold"},
    )
    return token, "synthetic-scaffold"


def call(
    method: str,
    path: str,
    persona: str = "invoice-reader",
    *,
    omit_dpop: bool = False,
    mismatched_jkt: bool = False,
    expired: bool = False,
) -> tuple[int, str]:
    """
    Execute a single admission attempt. Named-kwargs control the deny-path
    variants for Phase-2 scenario coverage.
    """
    dpop_key = gen_dpop_key()
    dpop_jwk = jwk_from_public_ec(dpop_key.public_key())
    real_jkt = jwk_thumbprint(dpop_jwk)
    url = f"{GATEWAY_URL}{path}"

    if os.environ.get("GATEWAY_TEST_MODE") != "synthetic":
        print(
            "Real AD FS token acquisition not yet implemented; "
            "set GATEWAY_TEST_MODE=synthetic"
        )
        return -1, ""

    # cnf-jkt-mismatch: cnf.jkt encodes a different key than the DPoP proof.
    if mismatched_jkt:
        other = gen_dpop_key()
        token_jkt = jwk_thumbprint(jwk_from_public_ec(other.public_key()))
    else:
        token_jkt = real_jkt

    exp_offset = -60 if expired else 60
    token, _ = synthetic_token(persona, token_jkt, exp_offset=exp_offset)

    headers = {"Authorization": f"Bearer {token}"}
    if not omit_dpop:
        headers["DPoP"] = make_dpop_proof(dpop_key, method, url)

    with httpx.Client(verify=False, timeout=30.0) as c:
        r = c.request(method, url, headers=headers)
    print(f"{persona} {method} {url} -> {r.status_code}")
    print(r.text[:800])
    return r.status_code, r.text


def run_scenario(name: str) -> tuple[int, str, str]:
    """
    Run one named scenario. Returns (status_code, response_body, expectation).
    """
    scenarios = {
        "happy-path": lambda: (
            call("GET", "/invoices/1", persona="invoice-reader"),
            "expect 200",
        ),
        "envelope-purpose-miss": lambda: (
            call("GET", "/invoices/1", persona="ticket-reader"),
            "expect 403 at step 4 (structural)",
        ),
        "envelope-method-miss": lambda: (
            call("POST", "/invoices/1", persona="invoice-reader"),
            "expect 403 at step 4 (structural)",
        ),
        "missing-dpop": lambda: (
            call("GET", "/invoices/1", persona="invoice-reader", omit_dpop=True),
            "expect 401 at step 2 (dpop)",
        ),
        "cnf-jkt-mismatch": lambda: (
            call("GET", "/invoices/1", persona="invoice-reader", mismatched_jkt=True),
            "expect 401 at step 2 (dpop)",
        ),
        "expired-token": lambda: (
            call("GET", "/invoices/1", persona="invoice-reader", expired=True),
            "expect 401 at step 1 (jwks)",
        ),
        "revoked-user-deny": lambda: (
            call("GET", "/invoices/1", persona="revoked-user"),
            "expect 403 at step 5 (gust)",
        ),
        "enumeration-sweep": lambda: run_enumeration_sweep(),
    }
    if name not in scenarios:
        print(f"unknown scenario: {name}")
        print("known scenarios:", ", ".join(scenarios))
        return -1, "", ""
    result = scenarios[name]()
    # Scenarios return either ((status, body), expectation)
    # OR (status, body) for the enumeration-sweep style.
    if isinstance(result, tuple) and len(result) == 2:
        first, second = result
        if isinstance(first, tuple) and len(first) == 2:
            (status, body) = first
            return status, body, str(second)
        return first, str(second), ""
    return -1, "", ""


def run_enumeration_sweep() -> tuple[int, str]:
    """
    A2 test per Alpha attack-tree: iterate /invoices/{1..20}.
    All should return 200 because each request is envelope-valid.
    Structural gate has no view into value-abuse aggregate;
    delta detector catches volume/spread in Phase 4.
    """
    statuses = []
    for i in range(1, 21):
        s, _ = call("GET", f"/invoices/{i}", persona="invoice-reader")
        statuses.append(s)
    ok = sum(1 for s in statuses if s == 200)
    print(f"enumeration-sweep: {ok}/20 admitted (expect 20 - correct-by-design)")
    return statuses[-1] if statuses else -1, str(statuses)


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]
    if cmd == "health":
        with httpx.Client(verify=False) as c:
            r = c.get(f"{GATEWAY_URL}/health")
        print(r.status_code, r.text)
    elif cmd == "jwks":
        with httpx.Client(verify=False) as c:
            r = c.get(f"{GATEWAY_URL}/jwks-preview")
        print(r.status_code, r.text)
    elif cmd == "persona":
        if len(sys.argv) < 5:
            print("usage: persona <name> <METHOD> <path>")
            return
        call(sys.argv[3], sys.argv[4], persona=sys.argv[2])
    elif cmd == "scenario":
        if len(sys.argv) < 3:
            print("usage: scenario <name>")
            return
        run_scenario(sys.argv[2])
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
