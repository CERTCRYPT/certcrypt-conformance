# V030 — Settlement Material Diverges From Signed settlement_ref

settlement_action.trx_id (unsigned) is swapped while the proof's signed
settlement_ref is left intact, so the material no longer matches what the
system domain signed.
Expected: INDEPENDENT_INVALID (SETTLEMENT_REF_VALID)