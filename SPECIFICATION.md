# IBAE: Intent-Bound Action Envelope Protocol

## An Open Specification for Purpose-Scoped Security in AI Agent Runtimes

**Version:** 0.1 (Draft for Review)
**Authors:** ISECOM / Griffin Cyber Solutions
**License:** Creative Commons Attribution-ShareAlike 3.0 (CC BY-SA 3.0)
**Status:** Draft

---

## 1. Problem Statement

AI agents interact with tools, APIs, and services through increasingly standardized protocols (MCP, OpenAI function calling, LangChain tool interfaces). The agent presents credentials, the service checks authorization, the call executes.

What's missing: a mechanism to constrain an agent's actions to the scope of its declared purpose, enforce that constraint at the infrastructure layer (not inside the agent), and detect when agent behavior drifts from the declared intent across a session.

Current efforts address adjacent problems but leave this gap:

- **Harness integration APIs** (OWASP ACS) standardize how agents connect to runtimes but don't constrain what they do once connected.
- **MCP authorization** (AuthZen COAZ) handles "is this identity allowed to call this tool" but not "is this tool call consistent with the agent's stated purpose."
- **MCP call interception** (Agentic AI Foundation MCP Interceptors) provides a hook point at the call layer but defines no decision vocabulary.
- **Capability taxonomies** (CSA AARM) catalog what agents can do but define no wire protocol, enforcement point, or integration API.

IBAE fills the gap: a protocol for purpose-scoped action-space bounding with per-request cryptographic proof, enforceable at a Policy Enforcement Point (PEP) that sits between the agent and the tools it calls.

---

## 2. Core Concepts

### 2.1 Purpose Declaration

An agent (or the orchestration layer managing it) declares a **purpose** before beginning a task. A purpose is a bounded scope of work: "read-invoices," "deploy-staging," "analyze-logs." The purpose is not a permission grant. It is a constraint envelope that limits which actions are structurally permitted for the duration of that purpose window.

The purpose declaration is made by the orchestration layer, not the agent itself. An agent cannot self-declare a wider purpose than its orchestrator assigns. This is the foundational trust boundary: the agent operates within the envelope; it does not define the envelope.

### 2.2 Action Envelope

Each purpose maps to an **action envelope**: a set of allowed tool calls, methods, parameter patterns, and resource paths. The envelope is defined in a policy file at deployment time, not at runtime.

Example envelope for purpose `read-invoices`:

```yaml
purposes:
  read-invoices:
    allowed:
      - tool: accounting-api
        methods: [GET]
        paths: ["/invoices/*", "/invoices/*/line-items"]
      - tool: reporting-api
        methods: [GET]
        paths: ["/reports/invoice-summary"]
    denied:
      - tool: accounting-api
        methods: [POST, PUT, DELETE]
        paths: ["*"]
```

Any call outside the envelope is denied before it reaches the downstream service. The denial is structural: no parameter value, prompt content, or runtime condition can override it. The envelope is the ceiling.

### 2.3 DPoP-Bound Purpose Tokens

Each purpose window is represented by a **purpose token**: a signed JWT carrying the agent's identity, role, purpose, and a cryptographic binding to an ephemeral key pair.

The binding follows the DPoP (Demonstrating Proof-of-Possession) pattern from RFC 9449. The purpose token carries a `cnf.jkt` claim containing the SHA-256 thumbprint of the agent's ephemeral public key. On each request, the agent also sends a **DPoP proof**: a separate JWT signed with the corresponding ephemeral private key, containing the HTTP method, target URI, and timestamp of the specific request.

This proves two things:
1. The agent presenting the purpose token is the same agent the token was issued to (possession of the ephemeral private key).
2. The token is being used for this specific request at this specific time (method, URI, and timestamp bound into the proof).

A stolen purpose token is useless without the ephemeral private key. A replayed DPoP proof fails because the timestamp and request details won't match.

### 2.4 Session Delta Detection

Purpose envelopes catch structurally invalid calls. They do not catch an agent that stays within its structural permissions but drifts in behavior: making increasingly aggressive queries, concentrating on a single resource, or exhibiting patterns consistent with prompt injection or goal drift.

The **delta detector** monitors the agent's behavior across the session and flags anomalous patterns. It operates on the stream of (permitted) actions the agent takes, not on the content of those actions. It answers: "Is this session's behavior distribution drifting from baseline for this purpose?"

The delta detection interface is defined; the detection algorithm is implementation-specific. Different deployments may use different detection strategies depending on their threat model and operational context.

### 2.5 Append-Only Audit Ledger

Every enforcement decision (permit, deny, flag) is written to an **append-only ledger**. The ledger is the forensic record: what the agent asked to do, what the gateway decided, and why.

Ledger entries are immutable once written. The ledger is the ground truth for post-incident analysis, compliance reporting, and RAV (Risk Assessment Value) computation.

---

## 3. Token Specification

### 3.1 Purpose Token (Access Token)

A purpose token is a signed JWT with the following claims:

| Claim | Type | Required | Description |
|-------|------|----------|-------------|
| `sub` | string | yes | Agent or service account identifier |
| `role` | string | yes | Role ceiling (maps to policy-defined permission set) |
| `provenance` | string | yes | Origin of the agent's identity (IdP, orchestrator, deployment context) |
| `purpose` | string | yes | Declared purpose identifier (must match a policy-defined envelope) |
| `exp` | number | yes | Expiration timestamp (Unix epoch). Defines the purpose window. |
| `cnf` | object | yes | Confirmation claim per RFC 7800. Must contain `jkt`: the base64url-encoded SHA-256 thumbprint of the agent's ephemeral public key, computed per RFC 7638. |

The token is signed by the **token issuer** (the identity provider or wrapping issuer in the deployment). The signing algorithm must be asymmetric (RS256, ES256, or equivalent). The gateway validates the signature against the issuer's published JWKS.

**Purpose window:** The token's `exp` defines a window (recommended default: 60 seconds) during which the token is valid for multiple requests under the same purpose. The agent does not need a new token for each request within the window. This bounds the load on the token issuer to one mint per purpose per window, not one per request.

### 3.2 DPoP Proof

A DPoP proof is a JWT signed by the agent's ephemeral private key, sent alongside the purpose token on each request:

| Claim | Type | Required | Description |
|-------|------|----------|-------------|
| `htm` | string | yes | HTTP method of the request (e.g., "GET", "POST") |
| `htu` | string | yes | Target URI of the request |
| `iat` | number | yes | Issued-at timestamp (Unix epoch) |
| `jti` | string | yes | Unique identifier for this proof (for replay detection) |

The proof's header carries the ephemeral public key in the `jwk` field.

### 3.3 Token Delivery

- Purpose token: sent in the `Authorization` header as a Bearer token.
- DPoP proof: sent in the `DPoP` header.

Both headers are present on every request to the gateway.

---

## 4. Gateway Enforcement Protocol

The gateway (PEP) sits between the agent and the downstream tools/services. Every request passes through the gateway. The downstream services accept connections only from the gateway, not from agents directly.

### 4.1 Request Processing Pipeline

For each inbound request, the gateway executes the following steps in order:

1. **Token validation.** Verify the purpose token's signature against the issuer's JWKS. Check `exp` is in the future. Extract `purpose`, `role`, `sub`, and `cnf.jkt`.

2. **DPoP proof validation.**
   - Verify the DPoP proof's signature against the ephemeral public key in its `jwk` header.
   - Compute the SHA-256 thumbprint of that public key per RFC 7638.
   - Confirm the thumbprint matches the purpose token's `cnf.jkt`.
   - Confirm `htm` matches the request method and `htu` matches the request URI.
   - Confirm `iat` is within the acceptance window (recommended: +/- 30 seconds).
   - Confirm `jti` has not been seen within the acceptance window (replay rejection).

3. **Envelope check.** Look up the action envelope for the token's `purpose` in the policy file. Check whether the requested tool, method, and path are permitted by the envelope. If not, deny.

4. **Content scanning (optional, implementation-defined).** Scan outbound request parameters for content-layer threats (prompt injection, data exfiltration markers, social engineering patterns). This layer is implementation-specific and not required by the base protocol.

5. **Forward or deny.** If all checks pass, forward the request to the downstream service. If any check fails, return a structured error to the agent and log the denial.

6. **Inbound response scanning (optional, implementation-defined).** Scan the downstream service's response before forwarding it to the agent. Detect poisoned responses (injected instructions, exfiltration payloads) that could steer the agent's subsequent behavior.

7. **Delta detection update.** Feed the (permitted) action into the session delta detector. If the detector flags anomalous drift, escalate per deployment policy (alert, throttle, or halt).

8. **Ledger write.** Write the enforcement decision (permit, deny, flag, or escalate) to the append-only ledger with full context.

### 4.2 Enforcement Decisions

| Decision | Meaning | Ledger Entry |
|----------|---------|--------------|
| `PERMIT` | All checks passed. Request forwarded. | Action, purpose, timestamp, downstream response status. |
| `DENY` | Request blocked. Sub-code indicates reason. | Attempted action, purpose, denial sub-code, implementation-specific details. |
| `FLAG` | Anomalous pattern detected. Action per policy. | Flag sub-code, implementation-specific metrics, escalation action taken. |

Implementations SHOULD emit sub-codes (e.g., `DENY:ENVELOPE`, `DENY:TOKEN`, `FLAG:DRIFT`) for operational visibility. Sub-code vocabularies are implementation-defined and not part of this protocol specification.

### 4.3 Error Responses

When the gateway denies a request, it returns a structured JSON error:

```json
{
  "error": "envelope_violation",
  "purpose": "read-invoices",
  "attempted": {
    "tool": "accounting-api",
    "method": "DELETE",
    "path": "/invoices/12345"
  },
  "message": "DELETE /invoices/* is not permitted for purpose read-invoices"
}
```

The error tells the agent what it tried and why it was denied. It does not reveal the full policy or other permitted actions.

---

## 5. Policy File Format

Policies are defined in YAML and compiled at deployment time (not interpreted at request time).

### 5.1 Structure

```yaml
issuer:
  jwks_uri: "https://idp.example.com/.well-known/jwks.json"
  audience: "intentguard"
  clock_skew_seconds: 30

dpop:
  acceptance_window_seconds: 30
  replay_cache_ttl_seconds: 60

roles:
  analyst:
    purposes: [read-invoices, read-reports]
  admin:
    purposes: [read-invoices, read-reports, write-invoices, manage-users]

purposes:
  read-invoices:
    token_lifetime_seconds: 60
    allowed:
      - tool: accounting-api
        methods: [GET]
        paths: ["/invoices/*", "/invoices/*/line-items"]
    denied:
      - tool: accounting-api
        methods: [POST, PUT, DELETE]
        paths: ["*"]

  write-invoices:
    token_lifetime_seconds: 30
    allowed:
      - tool: accounting-api
        methods: [GET, POST, PUT]
        paths: ["/invoices/*"]
    denied:
      - tool: accounting-api
        methods: [DELETE]
        paths: ["*"]

delta:
  enabled: true
  window_size: 50
  escalation: alert
```

### 5.2 Policy Evaluation Rules

- **Deny takes precedence.** If an action matches both an `allowed` and a `denied` rule, it is denied.
- **Default deny.** Any action not explicitly allowed is denied.
- **Role ceiling.** An agent's role limits which purposes it can request tokens for. A token minted for a purpose not in the role's list is rejected at the gateway.
- **Path wildcards.** `*` matches one path segment. `**` matches zero or more segments.

---

## 6. Delta Detection Interface

The delta detector is a component of the gateway that monitors session-level behavioral patterns. The detection algorithm is implementation-specific, but the interface is standardized.

### 6.1 Input

The detector receives a stream of permitted actions for each active session:

```json
{
  "session_id": "abc-123",
  "timestamp": 1698412800,
  "purpose": "read-invoices",
  "tool": "accounting-api",
  "method": "GET",
  "path": "/invoices/98765",
  "response_status": 200
}
```

### 6.2 Output

The detector emits a signal when drift exceeds a configured threshold:

```json
{
  "session_id": "abc-123",
  "signal": "FLAG_DELTA",
  "metric": "resource_concentration",
  "value": 0.87,
  "threshold": 0.75,
  "description": "Session shows high concentration on single resource path",
  "recommended_action": "alert"
}
```

### 6.3 Escalation Actions

Escalation is deployment-configured, not protocol-mandated. Recommended escalation ladder:

1. **Alert** -- notify the operator, continue forwarding.
2. **Throttle** -- reduce the agent's request rate.
3. **Curtail** -- restrict the agent to a narrower envelope subset.
4. **Halt** -- stop forwarding requests, require human intervention.

The escalation ladder is graduated. A single delta signal should not trigger a halt unless the deployment's threat model specifically requires it.

---

## 7. Ledger Schema

Every enforcement decision writes a ledger entry:

```json
{
  "id": "ledger-entry-uuid",
  "timestamp": "2026-10-27T20:15:00.000Z",
  "session_id": "abc-123",
  "agent_sub": "agent-007",
  "purpose": "read-invoices",
  "action": {
    "tool": "accounting-api",
    "method": "GET",
    "path": "/invoices/98765"
  },
  "decision": "PERMIT",
  "enforcement_details": {},
  "dpop_jti": "unique-proof-id",
  "downstream_status": 200
}
```

For denials:

```json
{
  "id": "ledger-entry-uuid",
  "timestamp": "2026-10-27T20:15:01.000Z",
  "session_id": "abc-123",
  "agent_sub": "agent-007",
  "purpose": "read-invoices",
  "action": {
    "tool": "accounting-api",
    "method": "DELETE",
    "path": "/invoices/98765"
  },
  "decision": "DENY_ENVELOPE",
  "enforcement_details": {
    "rule": "DELETE not in allowed methods for read-invoices",
    "policy_version": "1.0.0"
  }
}
```

The ledger is append-only. Entries are never modified or deleted. The ledger format is extensible: implementations may add fields for content-scan results, delta-detection metrics, or deployment-specific context.

---

## 8. Integration Patterns

IBAE is substrate-agnostic. The protocol defines the token format, the enforcement pipeline, and the policy schema. The deployment chooses how to issue tokens and how to deploy the gateway.

### 8.1 Pattern A: Wrapping Issuer

For deployments with an existing identity provider (AD FS, Keycloak, Dex, Auth0, any OIDC-compliant IdP) that does not natively support DPoP or purpose claims:

1. Agent authenticates to the IdP using standard client credentials or device flow.
2. The IdP issues a standard access token (identity proof only).
3. A **wrapping issuer** (a lightweight service) validates the IdP token, then mints a purpose-scoped IBAE token with `cnf.jkt` binding.
4. The agent uses the IBAE token + DPoP proof for all subsequent requests to the gateway.

The wrapping issuer bridges the gap between what existing IdPs provide and what IBAE requires. It adds purpose scope and DPoP binding on top of the IdP's authentication.

### 8.2 Pattern B: Native DPoP Issuer

For deployments where the IdP natively supports DPoP (RFC 9449) and custom claims:

1. Agent sends a DPoP proof with its token request.
2. The IdP mints a purpose-scoped token with `cnf.jkt` directly.
3. No wrapping issuer needed.

### 8.3 Pattern C: mTLS-Bound Tokens

For overlay network deployments (e.g., OpenZiti, WireGuard-based meshes) where endpoints already have strong certificate-based identity:

1. Agent's mTLS certificate provides identity.
2. Token binding uses RFC 8705 (certificate thumbprint in `cnf.x5t#S256`) instead of DPoP.
3. Per-request proof is implicit in the mTLS handshake rather than a separate JWT.

The gateway enforcement pipeline is identical across all three patterns. Only the token-binding verification step differs.

### 8.4 Protocol Adapters

IBAE enforcement can wrap any tool-calling protocol:

- **MCP (Model Context Protocol):** Gateway acts as an MCP stdio or SSE proxy. Agent connects to the gateway as if it were the MCP server.
- **OpenAI function calling:** Gateway intercepts HTTP calls to the function-execution endpoint.
- **REST APIs:** Gateway acts as a reverse proxy in front of the API.
- **LangChain / other frameworks:** Framework adapter translates tool calls into HTTP requests routed through the gateway.

The adapter translates protocol-specific call formats into the gateway's canonical (tool, method, path, parameters) tuple. The enforcement pipeline operates on the canonical form.

---

## 9. Security Properties

When correctly deployed, IBAE provides:

1. **Action-space bounding.** An agent cannot call tools or methods outside its declared purpose envelope, regardless of prompt content, model behavior, or runtime conditions.

2. **Cryptographic request binding.** Each request is bound to a specific agent, purpose, method, URI, and timestamp. Token theft, replay, and method-swapping are structurally prevented.

3. **Infrastructure-layer enforcement.** The gateway enforces policy. The agent's cooperation is not required. A compromised, jailbroken, or prompt-injected agent that tries to exceed its envelope is blocked at the gateway before the request reaches the downstream service.

4. **Behavioral drift detection.** Session-level monitoring catches anomalous patterns that pass structural checks. The delta detector provides a second detection axis orthogonal to envelope enforcement.

5. **Forensic completeness.** The append-only ledger provides a full, immutable record of every enforcement decision for post-incident analysis and compliance.

---

## 10. What This Spec Does Not Cover

This specification defines the open protocol: token format, enforcement pipeline, policy schema, delta-detection interface, and ledger schema. It does not define:

- Specific delta-detection algorithms
- Content-scanning implementations
- Production deployment architecture (load balancing, high availability, key rotation)
- Multi-tenant isolation patterns
- Pricing, licensing, or commercial terms for implementations

These are implementation-specific and may vary across vendors, deployments, and threat models. The protocol is the interoperability surface; the implementation is the product.

---

## Attribution

IBAE is grounded in the security measurement framework of the **Open Source Security Testing Methodology Manual (OSSTMM)**, maintained by the **Institute for Security and Open Methodologies (ISECOM)**. The OSSTMM concepts of Trust as measurable debt, operational controls (Confinement, Scrutiny, Tethering), and Risk Assessment Values (RAV) inform the protocol's design philosophy: security as a measurable, reducible quantity rather than a binary trust decision.

---

*This is an open specification. Implementations are encouraged. Feedback via GitHub Issues on this repository.*
