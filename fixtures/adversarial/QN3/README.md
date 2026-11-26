# QN3 — Duplicate Member Signature Counts Once (Anti-Stuffing)

Member m0 signs twice. Duplicate signer_member_kid values count as one
distinct member, so the quorum reaches only 1 < k=2.
Expected: REJECTED (FOUNDATION_SIGNATURE_VALID)