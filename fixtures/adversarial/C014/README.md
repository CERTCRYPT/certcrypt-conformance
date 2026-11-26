# C014 — Published Payload Digest Mismatch

The top-level `payload_canon_digest_hex` is not SHA3-256(JCS(payload)).
A published digest is recomputed and a mismatch fails closed (CCSP/1 §7.5).
Expected: REJECTED (BASE_CERTIFICATE_STRUCTURE_VALID)