# V056 — Finality Witness Disagrees With the Settlement Material

P001 whose finality witness declares `block_height` one ledger after the
settlement material's `finality_proof.block_num`. The witness is a projection
of the material (independence.proof/1 §10.6): `block_height` and `timestamp`
must equal `block_num` and `block_timestamp`.
Expected: REJECTED (FINALITY_SUFFICIENT)