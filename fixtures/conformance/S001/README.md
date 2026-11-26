# S001 — Valid Base Certificate Authenticity

The issuer's composite signature (P-256 + ML-DSA-65, AND) over the payload
is real, on the hybrid leaf=subtree model. Tests that
BASE_CERTIFICATE_AUTHENTIC passes: both components verify.
Expected: INDEPENDENT_VALID