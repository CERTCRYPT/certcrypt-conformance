# QN7 — Successor Binding With a Tampered Member Signature

m0's signature verifies; m1's ML-DSA-65 component is corrupted. The composite
verifies AND over both components, so m1 does not count and only 1 distinct
member verifies < k=2.
Expected: REJECTED (FOUNDATION_SUCCESSOR_QUORUM_VALID)