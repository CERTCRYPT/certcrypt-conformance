# V034 — Settlement Is Retroactive (block time after expiry)

settlement_material.finality_proof.block_timestamp is AFTER the capacity
commitment's expires_at: the on-chain burn landed once the capacity had
already expired (2026-05-11T12:00:00Z). Finality is otherwise sufficient, so the
temporal no-retroactivity check is the isolated break. The block time is the
substrate's own (never asserted by the issuing system).
Expected: INDEPENDENT_INVALID (SETTLEMENT_NOT_RETROACTIVE)