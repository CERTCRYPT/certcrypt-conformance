# S010 — ECDSA Component Declares low_s false

The ECDSA component is a valid low-s signature but declares low_s: false. The
field's value is fixed to true (composite-signature/1 §9.1).
Expected: REJECTED (PROOF_SIGNATURE_VALID)