# V053 — proof_id Not Derived From the Identity View

P001 whose `proof_id` is an arbitrary digest, signed as such by the system
domain. The signature verifies; `proof_id` does not equal
SHA3-256(JCS(identity view)) (independence.proof/1 §10.3.1).
Expected: REJECTED (PROOF_STRUCTURE_VALID)