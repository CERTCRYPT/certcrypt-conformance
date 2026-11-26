# QN8 — Duplicate Signer Counted Once

Bootstrap member m0 signs the successor binding twice. Duplicate
signer_member_kid values count as one distinct member (system-manifest/1
§12.3), so the quorum reaches only 1 < k=2.
Expected: REJECTED (FOUNDATION_SUCCESSOR_QUORUM_VALID)