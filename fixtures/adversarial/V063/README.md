# V063 — Finality Proof Without block_id

finality_proof.block_id is empty. It is the hash of the validated ledger
that includes the settlement and MUST be present and non-empty
(settlement.aggregated.xrpl/1 §8.3, §11.3).
Expected: REJECTED (FINALITY_SUFFICIENT)