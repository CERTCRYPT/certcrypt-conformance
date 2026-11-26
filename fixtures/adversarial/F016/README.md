# F016 — Root Under the Ed25519 Profile

The bootstrap entry declares certcrypt-composite-ed25519-mldsa65-v1. That
profile MUST NOT be the default of a system-foundation root
(composite-signature/1 §7), and the verifier supports the canonical profile
for the root.
Expected: REJECTED (FOUNDATION_FINGERPRINT_RECOMPUTED)