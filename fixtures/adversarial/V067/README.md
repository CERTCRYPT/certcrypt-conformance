# V067 — Unsupported Collection Commitment Scheme

The collection declares commitment_scheme collection.merkle-sha3-512/1, which
the verifier does not implement. Comparing the delivered leaves needs the
scheme, so the comparison fails closed as UNSUPPORTED — no fallback to another
scheme (verifier-toolkit/1 §8.4, §8.5.1).
Expected: UNSUPPORTED (ORIGINAL_MATERIAL_COMPARISON_VALID)