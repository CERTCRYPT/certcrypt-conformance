# F008 — Capacity-Key Substitution (Signed-Payload Coverage)

The Level-1 composite capacity key — which signs the IndependenceProof and
the capacity Level-1 binding — is swapped for an attacker key while the
original statement signature is left intact. Because the capacity key is
covered by the statement signature, the swap invalidates it.
Expected: REJECTED (FOUNDATION_SIGNATURE_VALID)