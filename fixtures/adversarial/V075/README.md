# V075 — independence_result Is Not `independent`

P001 whose independence proof carries `independence_result: "rejected"`, with
proof_digest recomputed. The member is outside the signed view, so the signature
still verifies. Under /1 the value is exactly `independent`; any other value is a
malformed proof, never read as a result (independence.proof/1 §10.10, §12.1).
Expected: REJECTED (PROOF_STRUCTURE_VALID)