# QN1 — Insufficient Quorum (k-1 signatures)

Only 1 valid member signature is present against a k=2 bootstrap entry.
Fewer than quorum.k distinct members verify → the statement is not
self-anchored.
Expected: REJECTED (FOUNDATION_SIGNATURE_VALID)