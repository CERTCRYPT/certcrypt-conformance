# V058 — Non-Zero Action Ordinal Named By The Signed Reference

settlement_action.action_ordinal is `1` and the signed settlement_ref names
the same ordinal, so the two agree. The profile defines no sub-position
inside a transaction and requires `0` (settlement.aggregated.xrpl/1 §8.1).
Expected: INDEPENDENT_INVALID (SETTLEMENT_REF_VALID)