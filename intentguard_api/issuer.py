"""IntentGuard Purpose Issuer - Generic OIDC-compatible purpose token minter.

Endpoints:
- GET  /jwks     -> JWKS with the signing pubkey (RSA)
- POST /mint     -> mint a purpose-scoped DPoP-bound access token
- GET  /healthz  -> liveness

POST /mint body:
    {
        "identity":    "<service account or user principal>",
        "role":        "<role name>",
        "purpose":     "<purpose string, e.g. read-invoices>",
        "exp_seconds": <int, default 60>,
        "cnf_jkt":     "<base64url SHA-256 thumbprint of caller's ephemeral DPoP pubkey>"
    }

In production, the identity would come from upstream OIDC/OAuth (Auth0, Okta,
Keycloak, etc.), not from the request body. This issuer wraps any upstream
identity provider's auth with purpose-binding claims.
"""

import base64
import json
import os
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request

KEYS_DIR = Path(__file__).parent / "keys"
KEY_ID = "intentguard-api-key-1"
ISSUER = "https://issuer.intentguard.local"


def _load_or_create_signing_key():
    KEYS_DIR.mkdir(exist_ok=True)
    priv_path = KEYS_DIR / f"{KEY_ID}.pem"
    if priv_path.exists():
        return serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    return key


def _b64url_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _jwks_entry(pub) -> dict:
    numbers = pub.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "kid": KEY_ID,
        "alg": "RS256",
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }


def create_app():
    app = Flask(__name__)
    signing_key = _load_or_create_signing_key()
    signing_pem = signing_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    jwks = {"keys": [_jwks_entry(signing_key.public_key())]}

    @app.get("/jwks")
    def jwks_endpoint():
        return jsonify(jwks)

    @app.get("/healthz")
    def healthz():
        return jsonify({"ok": True, "issuer": ISSUER, "mode": "api"})

    @app.post("/mint")
    def mint():
        body = request.get_json(force=True)
        for required in ("identity", "role", "purpose", "cnf_jkt"):
            if required not in body:
                return jsonify({"error": f"missing field: {required}"}), 400
        exp_seconds = int(body.get("exp_seconds", 60))
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "sub": body["identity"],
            "role": body["role"],
            "provenance": f"{ISSUER}#{KEY_ID}",
            "purpose": body["purpose"],
            "exp": now + exp_seconds,
            "iat": now,
            "cnf": {"jkt": body["cnf_jkt"]},
        }
        token = jwt.encode(
            claims,
            signing_pem,
            algorithm="RS256",
            headers={"kid": KEY_ID, "typ": "JWT"},
        )
        return jsonify({"access_token": token})

    return app


if __name__ == "__main__":
    port = int(os.environ.get("ISSUER_PORT", "8710"))
    create_app().run(host="127.0.0.1", port=port, debug=False)
