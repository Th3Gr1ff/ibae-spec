"""E2E: mint access token → build DPoP-proof → verify the full spec §6 chain.

Runs entirely in-process against the mock harness's Flask test client. No network.
Simulates what a gateway will do at admission time, so the mock and the AD-glue
code shake hands correctly before we swap in real AD FS.

Verification chain per spec §6 step 2:
    (a) DPoP-proof signature verifies with the jwk it carries
    (b) SHA-256 thumbprint of that jwk equals access token cnf.jkt
    (c) htm/htu match the request
    (d) iat within ±30s
    (e) jti not previously seen (dedupe)  — TODO in gateway lane, out of scope here

Also covers the negative cases the gateway will need to reject.
"""

import base64
import json
import sys
import time
from pathlib import Path

import jwt
import pytest
import requests

sys.path.insert(0, str(Path(__file__).parent.parent))

from ad_glue.client import PurposeTokenClient  # noqa: E402
from ad_glue.dpop import build_proof, jwk_thumbprint  # noqa: E402
from ad_glue.gmsa import GmsaIdentity  # noqa: E402
from ad_glue.keys import EphemeralKey  # noqa: E402

sys.path.insert(0, str(Path(__file__).parent.parent / "mock_ad_fs"))
from server import create_app  # noqa: E402

ACCEPT_WINDOW_SECONDS = 30


@pytest.fixture
def flask_client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture
def jwks_keys(flask_client):
    resp = flask_client.get("/jwks")
    assert resp.status_code == 200
    return resp.get_json()["keys"]


def _mint_via_test_client(flask_client, purpose: str, cnf_jkt: str) -> str:
    resp = flask_client.post("/mint", json={
        "identity": "svc-test-agent$",
        "role": "IBAE-ReadInvoices",
        "purpose": purpose,
        "exp_seconds": 60,
        "cnf_jkt": cnf_jkt,
    })
    assert resp.status_code == 200
    return resp.get_json()["access_token"]


def _jwk_to_pyjwt_key(jwk: dict):
    return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))


def _verify_full_chain(access_token: str, dpop_proof: str, http_method: str, http_url: str, jwks_keys: list):
    # (0) parse access token header to find kid
    at_header = jwt.get_unverified_header(access_token)
    matching_jwk = next(k for k in jwks_keys if k["kid"] == at_header["kid"])
    at_verify_key = _jwk_to_pyjwt_key(matching_jwk)
    at_claims = jwt.decode(access_token, at_verify_key, algorithms=["RS256"], options={"verify_aud": False})

    # (a) verify DPoP-proof signature with jwk in its header
    proof_header = jwt.get_unverified_header(dpop_proof)
    assert proof_header["typ"] == "dpop+jwt"
    assert proof_header["alg"] == "ES256"
    proof_jwk = proof_header["jwk"]
    proof_verify_key = jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(proof_jwk))
    proof_claims = jwt.decode(dpop_proof, proof_verify_key, algorithms=["ES256"])

    # (b) thumbprint match
    assert jwk_thumbprint(proof_jwk) == at_claims["cnf"]["jkt"]

    # (c) htm/htu match
    assert proof_claims["htm"] == http_method.upper()
    assert proof_claims["htu"] == http_url

    # (d) iat within ±window
    now = int(time.time())
    assert abs(now - proof_claims["iat"]) <= ACCEPT_WINDOW_SECONDS


def test_happy_path_mint_and_proof(flask_client, jwks_keys):
    key = EphemeralKey()
    access_token = _mint_via_test_client(flask_client, "read-invoices", jwk_thumbprint(key.public_jwk))
    dpop = build_proof(key, "GET", "https://api.ibae.lab/invoices")
    _verify_full_chain(access_token, dpop, "GET", "https://api.ibae.lab/invoices", jwks_keys)


def test_thumbprint_mismatch_is_rejected(flask_client, jwks_keys):
    key_a = EphemeralKey()
    key_b = EphemeralKey()
    access_token = _mint_via_test_client(flask_client, "read-invoices", jwk_thumbprint(key_a.public_jwk))
    dpop = build_proof(key_b, "GET", "https://api.ibae.lab/invoices")
    with pytest.raises(AssertionError):
        _verify_full_chain(access_token, dpop, "GET", "https://api.ibae.lab/invoices", jwks_keys)


def test_htm_mismatch_is_rejected(flask_client, jwks_keys):
    key = EphemeralKey()
    access_token = _mint_via_test_client(flask_client, "read-invoices", jwk_thumbprint(key.public_jwk))
    dpop = build_proof(key, "POST", "https://api.ibae.lab/invoices")
    with pytest.raises(AssertionError):
        _verify_full_chain(access_token, dpop, "GET", "https://api.ibae.lab/invoices", jwks_keys)


def test_htu_mismatch_is_rejected(flask_client, jwks_keys):
    key = EphemeralKey()
    access_token = _mint_via_test_client(flask_client, "read-invoices", jwk_thumbprint(key.public_jwk))
    dpop = build_proof(key, "GET", "https://api.ibae.lab/invoices/A")
    with pytest.raises(AssertionError):
        _verify_full_chain(access_token, dpop, "GET", "https://api.ibae.lab/invoices/B", jwks_keys)


def test_client_reuses_token_within_window(monkeypatch):
    """PurposeTokenClient caches the token for the purpose window."""
    minted = []

    class FakeResp:
        status_code = 200
        def raise_for_status(self): pass
        def json(self):
            return {"access_token": "fake-token"}

    def fake_post(url, json, timeout):
        minted.append(json)
        return FakeResp()

    monkeypatch.setattr(requests, "post", fake_post)
    identity = GmsaIdentity(sam_account_name="svc-x$", role="IBAE-ReadInvoices")
    client = PurposeTokenClient(mint_url="https://mock/mint", identity=identity, default_exp_seconds=60)

    key_1, token_1 = client.get("read-invoices")
    key_2, token_2 = client.get("read-invoices")

    assert token_1 == token_2 == "fake-token"
    assert key_1 is key_2
    assert len(minted) == 1


def test_client_remints_across_purposes(monkeypatch):
    """Different purposes = different ephemeral keys and different mint calls."""
    minted = []

    class FakeResp:
        status_code = 200
        def raise_for_status(self): pass
        def json(self):
            return {"access_token": "fake-token-" + str(len(minted))}

    def fake_post(url, json, timeout):
        minted.append(json)
        return FakeResp()

    monkeypatch.setattr(requests, "post", fake_post)
    identity = GmsaIdentity(sam_account_name="svc-x$", role="IBAE-ReadInvoices")
    client = PurposeTokenClient(mint_url="https://mock/mint", identity=identity, default_exp_seconds=60)

    key_a, _ = client.get("read-invoices")
    key_b, _ = client.get("write-invoices")

    assert key_a is not key_b
    assert len(minted) == 2
    assert minted[0]["purpose"] == "read-invoices"
    assert minted[1]["purpose"] == "write-invoices"
