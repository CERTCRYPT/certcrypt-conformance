# S002 — Invalid Signature Component

The ML-DSA-65 component's bytes are corrupted, so the composite (AND) must
fail. The cert is mutated before the ccd is computed, so the only failing
check is authenticity.
Expected: ISSUED_INVALID (BASE_CERTIFICATE_AUTHENTIC)