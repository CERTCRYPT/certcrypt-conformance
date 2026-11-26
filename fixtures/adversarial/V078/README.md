# V078 — Capacity Evidence With Non-Canonical Salt

The operation salt uses uppercase hexadecimal instead of lowercase hexadecimal bytes.

A verifier refuses the artifact before dereferencing or interpreting its members (capacity.evidence/1 Sections 4 to 8).
Expected: INDEPENDENT_INVALID (CAPACITY_EVIDENCE_VALID)