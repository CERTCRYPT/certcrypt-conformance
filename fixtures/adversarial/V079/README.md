# V079 — Capacity Commitment With Non-Canonical issued_at

The commitment instant uses an offset instead of RFC 3339 UTC with whole seconds.

A verifier refuses the artifact before dereferencing or interpreting its members (capacity.evidence/1 Sections 4 to 8).
Expected: INDEPENDENT_INVALID (CAPACITY_EVIDENCE_VALID)