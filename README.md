# IBAE — Intent-Bound Action Envelope (AD-glue lane)

OSSTMM v4 Intent-Bound Action Envelope architecture, this tree owns the **AD-glue lane**: intent-claim minting + AD FS/gMSA integration.

Spec is at `/home/pete/dev/ibae/spec/ibae_spec_v1_2026-08-31.md` (Kenna's box). Locked shape v1.1, 2026-08-31.

## Tree layout

- `mock_ad_fs/` — shared mock JWKS + purpose-mint harness. Any lane can point at this instead of a real DC. Contract in its own README.
- `ad_glue/` — this lane. Ephemeral DPoP key gen/rotate, purpose-window access token mint against AD FS (or mock), DPoP-proof JWT construction per request, gMSA identity abstraction.
- `tests/` — e2e round-trip: mint → DPoP-proof → verify against mock.

## Locked shape (do not drift from spec §3, §6)

- **Access token:** purpose-window lifetime (60s default), multi-use across window. Claims: `sub / role / provenance / purpose / exp + cnf.jkt`. No nonce.
- **DPoP-proof:** per-request, ephemeral-key signed. Header carries `jwk` (ephemeral pubkey). Payload: `htm / htu / iat / jti`.
- **Verification chain:** JWKS-verify access token → SHA-256 thumbprint of DPoP-proof `jwk` equals access token `cnf.jkt` → `htm`/`htu` match request → `iat` within ±30s → `jti` not in dedupe window.
- **Anti-replay** lives at the DPoP-proof layer (`jti` dedupe + `iat` window). Access token is a durable purpose grant.

## Escape hatch (post-v1)

Per-request access token minting (option a shape) available as a per-envelope policy flag. Sits at the policy-authoring-surface lane, not here.

## Status

- 2026-08-31: scaffolding started against mock JWKS + fake purpose-endpoint. Griff building the Windows Server 2022 AD lab VM from `ibae_ad_lab_2026-08-29.zip` (Kenna's kit) in parallel. Real AD FS URL swaps in for the mock at boundary once VM is clean.
