# S005 — Wrong Public Key For Valid Signature

The P-256 component was signed by a different key than the declared
pub_p256_b64, so the composite (AND) must fail.
Expected: ISSUED_INVALID (BASE_CERTIFICATE_AUTHENTIC)