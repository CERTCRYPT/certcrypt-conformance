# V037 — Foundation System-ID Mismatch

system-foundation/1 statement carries system_id "certcrypt-impostor", not the
verifier's configured system domain. system-foundation/1 §11 (step 2) rejects
before the quorum signature is even considered — the foundation-layer
system-domain binding.
Expected: REJECTED (FOUNDATION_SYSTEM_ID_VALID)