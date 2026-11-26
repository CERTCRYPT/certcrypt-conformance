# C001 — Envelope With Every Optional Member

The certificate carries `metadata`, `extensions`, an issuer `kid` and a
published `payload.anchor_canon_digest_hex` that matches its recomputation.
Arrays in metadata and extensions repeat elements, which is ordinary data,
not a repeated member name. The emission binding covers the whole
certificate, these members included (CCSP/1 §6.2).
Expected: INDEPENDENT_VALID