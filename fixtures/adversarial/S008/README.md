# S008 — Unsigned Proof of Independence

P001 with the proof's `signature` removed (`proof_digest` recomputed). The
signature is mandatory (independence.proof/1 §10.13): without it the signed
fields carry no authenticity, so the verifier cannot reach Independent.
Expected: INCOMPLETE (PROOF_SIGNATURE_VALID)