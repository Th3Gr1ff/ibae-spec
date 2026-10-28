# IBAE — Intent-Bound Action Envelope Protocol

An open specification for purpose-scoped security in AI agent runtimes.

IBAE bounds an agent's action space by declared intent, denying any request that deviates from the purpose the agent was granted at session start. The primitive is action-space bounding, not intent measurement.

## Specification

[SPECIFICATION.md](SPECIFICATION.md) contains the full protocol specification.

![IBAE Architecture](ibae_open_spec_diagram.png)

## Reference Implementation

This repository includes a reference implementation of the IBAE protocol:

### Core Modules

- **`intentguard_ai/`** — AI agent governance module: delta detection, DLP scanning, envelope enforcement, policy engine, and reverse proxy.
- **`intentguard_api/`** — 6-step admission pipeline implementing the IBAE verification chain:
  1. JWKS key resolution
  2. DPoP proof verification
  3. Envelope extraction
  4. Structural policy check
  5. GUST negative detection
  6. Admit/deny decision

### MVP Stack

- **`mvp/`** — Docker Compose stack with gateway, sidecar, BDD test harness, mock backend, mock Sentinel, and mock Splunk HEC for local development and testing.

### Tests

- **`tests/`** — End-to-end, DLP, AI governance, and pentest MCP server test suites.

### Policies

- **`intentguard_ai/policies/`** — Example YAML policy configurations for demo, pentest, and application-specific use cases.

### Analysis

- **`red_team/`** — Deny-on-delta attack tree analysis.

## Verification Chain

1. JWKS-verify the access token
2. SHA-256 thumbprint of the DPoP-proof ephemeral public key must equal the access token's `cnf.jkt`
3. `htm`/`htu` in the DPoP-proof must match the actual request method and URL
4. `iat` must be within the acceptance window (±30s)
5. `jti` must not appear in the deduplication window (anti-replay)

## Getting Started

```bash
# Clone and set up
git clone https://github.com/Th3Gr1ff/ibae-spec.git
cd ibae-spec
pip install -r requirements.txt

# Run the MVP stack
cd mvp
docker compose up

# Run tests
cd ..
pytest tests/
```

## Enterprise

This repository contains the open IBAE protocol specification and a reference implementation. For enterprise features including Active Directory integration, AD FS purpose-claim issuance, gMSA identity binding, and commercial support, contact Griffin Cyber Solutions at chris@griffincybersolutions.com.

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## Trademarks

IntentGuard and IntentGuard AI are trademarks of Griffin Cyber Solutions. The Apache 2.0 license grants you rights to use, modify, and distribute the code in this repository. It does not grant rights to use the IntentGuard name, logo, or trademarks in derivative works, forks, or commercial products without written permission from Griffin Cyber Solutions.
