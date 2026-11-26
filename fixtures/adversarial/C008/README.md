# C008 — issued_at With A Numeric Offset

`payload.anchor.issued_at` uses a `+02:00` offset. CCSP/1 §7.3.1 requires
UTC with the `Z` suffix, so every verifier reads the same instant.
Expected: REJECTED (BASE_CERTIFICATE_STRUCTURE_VALID)