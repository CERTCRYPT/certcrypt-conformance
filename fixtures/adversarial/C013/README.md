# C013 — Published Anchor Digest Mismatch

A correctly signed certificate publishes `payload.anchor_canon_digest_hex`
with a value that is not SHA3-256(JCS(anchor)). A published digest is
recomputed and a mismatch fails closed (CCCP/1 §7.3).
Expected: REJECTED (BASE_CERTIFICATE_STRUCTURE_VALID)