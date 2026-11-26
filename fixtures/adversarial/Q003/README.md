# Q003 — Composite With Broken ML-DSA-65 Component

The P-256 component is valid but the ML-DSA-65 component is corrupted.
Composite verification is AND: a broken PQC half fails the whole signature
(the post-quantum floor is mandatory, not a sidecar).
Also pins additional_verifications.pqc_base_certificate_authentic:
performed=true, passed=false — the component was verified and failed, so
the slot must not read `not_attempted`.
Expected: ISSUED_INVALID (BASE_CERTIFICATE_AUTHENTIC)