# V077 — Capacity Evidence Without projected_commitment

The capacity evidence omits the mandatory `projected_commitment` member.

A verifier refuses the artifact before dereferencing or interpreting its members (capacity.evidence/1 Sections 4 to 8).
Expected: INDEPENDENT_INVALID (CAPACITY_EVIDENCE_VALID)