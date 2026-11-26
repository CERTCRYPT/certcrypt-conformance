# C010 — Two Issuer Signatures

`signatures[]` carries the issuer signature twice. CCSP/1 §7.4 admits
exactly one signature object, so no verifier has to choose between them.
Expected: REJECTED (BASE_CERTIFICATE_STRUCTURE_VALID)