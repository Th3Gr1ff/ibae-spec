# IntentGuard Gateway MVP

Reverse-proxy that runs the IBAE v1.1 §6 six-step admission chain per request.

## Structure

- `gateway/` — FastAPI gateway (Phase 1: happy-path admits + step-4 deny, real JWKS via AD FS)
- `mock_backend/` — Backend behind the gateway that echoes what it receives
- `test_client/` — Python DPoP-signing client for smoke-testing
- `scripts/` — Phase-1 test runner

## Prereqs

- Docker + docker-compose installed on the host
- Host `/etc/hosts` has `100.87.4.63 fs.ibae.lab` (Tailscale IP of AD FS federation service)
- AD FS reachable at `https://fs.ibae.lab/adfs/discovery/keys`

## Bring up

```
cd /home/kenna/projects/ibae/mvp
docker compose up --build -d
docker compose logs -f gateway
```

## Phase-1 smoke tests

```
cd test_client
pip install -r requirements.txt
GATEWAY_TEST_MODE=synthetic python client.py health
GATEWAY_TEST_MODE=synthetic python client.py jwks
GATEWAY_TEST_MODE=synthetic python client.py admit /invoices/1
GATEWAY_TEST_MODE=synthetic python client.py deny  /admin/system
```

`GATEWAY_TEST_MODE=synthetic` uses a locally-signed token so scaffold-only
smoke testing can happen before the AD FS Purpose Issuer plugin (task #51)
mints real tokens. Real-AD-FS token acquisition happens once the plugin
lands and can inject the purpose + cnf.jkt claims into issued tokens.

## Six-step admission chain per v1.1 §6

1. `step1_jwks.py` — Access Token / JWKS Validation
2. `step2_dpop.py` — DPoP Proof Verification (with cnf.jkt binding)
3. `step3_envelope.py` — Purpose Envelope Decoding (server-set purpose → catalog lookup)
4. `step4_structural.py` — Structural Envelope Match (**the intent gate**, gold-accented in the architecture diagram)
5. `step5_gust.py` — GUST-Negative Cross-Check (Phase 1 stub; populated post-Behavioral-Delta-Detector)
6. `step6_decision.py` — Admit / Deny + OCSF Ledger Emission (terminal decision node)

## Roadmap

- **Phase 1** — happy path admits, envelope mismatch denies, real JWKS via AD FS. Current.
- **Phase 2** — full deny-path matrix (missing DPoP, cnf.jkt mismatch, expired warrant, GUST-neg simulation, wrong subject, replay). Includes A2 enumeration-sweep test.
- **Phase 3** — OCSF telemetry emission to SIEM connector. Sentinel + stdout NDJSON shipped, Splunk HEC added 2026-09-17 (same emitter also serves Cribl HEC listeners). Datadog Logs Intake + OTLP queued in `[[project-intenttrace-output-connectors]]`.

  SIEM_CONNECTOR env accepts a comma-separated list: `stdout`, `sentinel`, `splunk_hec`. `both` remains as a back-compat alias for `stdout,sentinel`. Example: `SIEM_CONNECTOR="stdout,sentinel,splunk_hec"` fans events to all three.

  Splunk HEC env vars: SPLUNK_HEC_ENDPOINT (base URL, /services/collector/event appended), SPLUNK_HEC_TOKEN (required), SPLUNK_HEC_SOURCETYPE (default "intenttrace:ocsf"), SPLUNK_HEC_INDEX (optional), SPLUNK_HEC_HOST (default "intenttrace-gateway"), SPLUNK_HEC_VERIFY_TLS ("true" to verify TLS; default false for lab). Mock HEC receiver at `./mock_splunk_hec/` exposes `GET /_received` for test-harness verification.
- **Phase 4** — Behavioral Delta Detector reading ledger + Sidecar Approval Channel notification to Signal.
