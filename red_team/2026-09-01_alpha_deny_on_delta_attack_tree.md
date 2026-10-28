# IBAE / IntentGuard — Deny-on-Delta Red-Team Attack Tree (spec/design layer)

**Author:** Alpha (deny-on-delta / envelope-mismatch slice)
**Target:** frozen v1.1 §6 admission chain + Behavioral Delta Detector (session layer)
**Layer:** design/spec — no running gateway required. Reconcile against canonical spec text on Pete/Kenna's box before treating any node as confirmed; built against my working model of v1.1 (8-step §6 chain, DPoP-bound purpose JWTs, GUST-negative cross-check, OCSF ledger, post-admission delta detector).
**Scope note:** DEFENSIVE red-team of our own design. Offensive tooling against third parties stays gated (Michael).

---

## Root goal (attacker)
> Get an action **admitted** (or a session sustained) that **deviates from declared purpose**, without tripping deny-on-delta.

The primitive is: *admit iff bound to a declared purpose envelope AND no delta from it.* So there are exactly three ways to beat it —
1. **Make the malicious action match the envelope** (defeat the structural gate, step 4).
2. **Make the deviation invisible to the delta layer** (defeat the session detector).
3. **Corrupt the inputs the gate/detector trust** (envelope, purpose, nonce, ledger).

Ranked by severity below. **A2, A4, B2, and C1 are the load-bearing ones** — the rest are tuning/hygiene.

---

## A. Defeat the structural envelope match (step 4 — the intent gate)

**A1 — Envelope over-broadening (coarse-grained purpose).**
Declare a purpose whose envelope is broad enough to legally contain the malicious action ("support read" that grants all customer reads). Structural match passes because the action *is* in scope.
- *Break:* the gate is only as tight as envelope granularity. Coarse envelopes admit malicious-but-in-scope actions by construction.
- *Test (Phase 2):* declared="read own ticket", action="read arbitrary ticket id" — must 403 only if envelope carries the id/param constraint.
- *Mitigation:* least-privilege envelope templates; bind purpose → concrete action-scope + parameter constraints, not just endpoint/verb.

**A2 — Structural ≠ semantic (the core weakness). ★**
Step 4 matches request *shape/fields*, not meaning. Two requests structurally identical, semantically divergent, both pass. `GET /records/{id}` matches the envelope for **every** id → enumerate/exfiltrate one structurally-valid request at a time.
- *Break:* a syntactic gate cannot see intent divergence that lives in parameter *values* or in aggregate. This is the fundamental ceiling of structural gating.
- *Test:* single-request enumeration sweep, each request individually envelope-valid; confirm nothing in step 4 stops it (by design it won't — this is what pushes detection to the delta layer, see B2).
- *Mitigation:* value-level constraints in the envelope where enumerable; treat volume/spread as a delta signal; do NOT let the pitch claim step 4 catches semantic abuse — it doesn't.

**A3 — Parser differential / envelope confusion (request-smuggling analog). ★**
Craft a request the gateway decodes as purpose X but the backend executes as Y (encoding, path normalization, duplicate headers, content-type ambiguity). The gate matches X; the backend does Y.
- *Break:* gateway and backend parse independently; any divergence = admitted-as-X, executed-as-Y.
- *Test:* mixed-encoding path, duplicate purpose header, trailing-dot/`..` normalization; compare gateway decode vs backend interpretation.
- *Mitigation:* canonicalize before match; gateway forwards the *normalized* request it actually matched (re-serialize), never the raw bytes; shared parse contract with backend.

**A4 — Envelope not cryptographically bound (MITM/swap). ★★**
If the purpose envelope rides as a sidecar header/body NOT covered by the JWT signature or the DPoP proof, an attacker (or a compromised client-side step) substitutes a benign envelope for a malicious request. Step 4 faithfully matches the *substituted* envelope.
- *Break:* the make-or-break question for the whole design — **is the envelope inside the signed material?** If envelope integrity depends on transport (TLS) only, it's swappable at any post-TLS hop (proxy, SSRF pivot, compromised sidecar).
- *Test:* strip/replace envelope header while preserving a valid DPoP proof + access token; must 403.
- *Mitigation:* envelope hash as a JWT claim (issuer-signed) OR envelope covered by the DPoP proof's signed component. The gate must verify envelope→token binding, not just envelope→request shape. **Flag for spec: confirm this binding is mandatory, not optional.**

---

## B. Evade the Behavioral Delta Detector (session layer, post-admission)

**B1 — Low-and-slow sub-resolution drift.**
Keep every request individually envelope-valid; shift trajectory slowly so per-window session delta stays under threshold.
- *Break:* threshold/window tuning; per-window scoring misses cumulative drift.
- *Mitigation:* cumulative, baseline-relative scoring anchored to declared intent, not a rolling window.

**B2 — Detector is detective, not preventive (architectural). ★★**
The detector reads the ledger **post-admission** — the deviating request is **already forwarded** before the delta fires. Any single high-blast-radius action (one exfil call, one destructive write) succeeds before session-scale detection can react.
- *Break:* deny-on-delta at session scale **cannot stop the first deviating action**, only subsequent ones. This is structural, not tunable.
- *Consequence for the pitch:* don't let "deny on delta" imply per-action prevention at the session layer. Prevention lives entirely in the synchronous step-4 gate; the detector is containment/response.
- *Mitigation:* for a declared set of high-blast-radius action classes, require the synchronous structural gate to be *sufficient on its own* (tight envelopes, A1/A2 closed), or inline the detector (synchronous hold-for-verdict) for those classes only — accepting the latency cost where blast radius justifies it.

**B3 — Baseline poisoning via Cell-D trajectory recovery (Rehberger). ★**
If the detector's "normal" baseline is learned from *observed* behavior, an attacker steers the agent off-course through error-recovery, and the anomalous trajectory gets absorbed into the baseline as normal.
- *Break:* observed-behavior baselines are game-able; this is exactly why structural and delta checks must stay separate (my Cell-D point).
- *Mitigation:* anchor the baseline to the **declared envelope**, not to behavioral history. Delta = distance from *declared intent*, never distance from *recent behavior*.

**B4 — Session-boundary reset.**
Split malicious activity across many short sessions so no single session accumulates enough delta.
- *Mitigation:* cross-session correlation by subject/principal; delta budget follows the principal, not the session id.

---

## C. Corrupt the inputs the gate trusts

**C1 — Self-declared purpose (foundational assumption). ★★**
Deny-on-delta only measures deviation *from the declared purpose.* If the calling agent **declares its own purpose**, it declares a benign purpose and then acts fully consistently with it — zero delta, admitted, malicious.
- *Break:* the entire model assumes the declared purpose is *authorized by someone other than the caller.* If purpose is caller-asserted, the gate verifies self-consistency, not legitimacy.
- *Test:* agent mints a broad-but-plausible purpose and operates entirely inside it; confirm nothing in the chain questions *whether that purpose should have been granted.*
- *Mitigation:* purpose issuance must be gated by policy/role/human at the Purpose Issuer — **the caller may request a purpose but must not be able to grant itself one.** This is the trust root of the product; state it explicitly in the spec.

**C2 — Nonce/DPoP replay TOCTOU.**
Single-use nonce defeats replay only if the burn is atomic. Two in-flight requests with the same nonce before the store commits (distributed gateway) = double-admit.
- *Mitigation:* atomic nonce burn; single nonce authority or consensus; short TTL.

**C3 — Expired-warrant grace / clock skew.**
60s purpose token + clock skew grace window lets a just-expired warrant through.
- *Mitigation:* tight, asymmetric skew bounds; reject rather than grace on the expiry edge.

---

## D. Blind the delta detector (ledger integrity)

**D1 — Ledger tampering / omission. ★**
The detector reads the OCSF ledger post-admission. Suppress or forge entries → detection goes blind even though the request was admitted.
- *Break:* "append-only" must be cryptographically enforced, not a filesystem promise.
- *Mitigation:* hash-chained/signed ledger; detector verifies chain continuity and refuses to score on a broken/lagging chain (fail-loud, not fail-open).

**D2 — Ledger lag / async emission.**
If emission is async and lags, the detection window widens — more deviating requests land before the detector sees them (compounds B2).
- *Mitigation:* bounded emission latency SLA; detector alarms on staleness.

---

## Top-4 to build against (hand these to Phase 2 first)
| # | Break point | Why it's load-bearing | Spec question to resolve |
|---|-------------|----------------------|--------------------------|
| **A4** | Envelope not crypto-bound to token | If true, the whole gate is bypassable by substitution | Is envelope→token binding mandatory and verified at step 4? |
| **C1** | Self-declared purpose | Gate verifies self-consistency, not legitimacy | Who authorizes purpose issuance — caller or independent authority? |
| **B2** | Delta is detective, not preventive | First deviating action always lands | Which action classes get synchronous (inline) treatment vs post-hoc? |
| **A2** | Structural ≠ semantic | Enumeration/value-abuse passes the gate by design | How fine-grained are envelope value constraints? |

**Net:** the synchronous step-4 gate is the *only* preventive control; everything at the session layer is containment. So the product's security reduces to (a) is the envelope trustworthy and tightly bound [A4/C1], and (b) is the gate tight enough that "admitted" genuinely means "non-malicious" [A1/A2/A3]. The delta detector is real value but must be sold as detection/response, not prevention.
