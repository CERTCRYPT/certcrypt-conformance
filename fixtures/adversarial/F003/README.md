# F003 — Invalid Foundation Signature

The ML-DSA-65 component of enough member statement_signatures is corrupted
that fewer than quorum.k distinct members verify. Composite verification is
AND, so each tampered member fails; the quorum is not met.
Expected: REJECTED (FOUNDATION_SIGNATURE_VALID)