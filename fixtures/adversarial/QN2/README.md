# QN2 — Non-Member Signature Does Not Count

Two signatures, but the second is from a key that is not a member of the
bootstrap entry (signer_member_kid 'not-a-member'). A non-member signature
never contributes to the quorum, so only 1 distinct member verifies < k=2.
Expected: REJECTED (FOUNDATION_SIGNATURE_VALID)