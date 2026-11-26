# QN6 — Successor Binding Signed by a Non-Member

m0 signs, and a second signature verifies under a key that is not a member of
the bootstrap entry (signer_member_kid 'not-a-member'). A non-member never
counts toward the quorum, so only 1 distinct member verifies < k=2.
Expected: REJECTED (FOUNDATION_SUCCESSOR_QUORUM_VALID)