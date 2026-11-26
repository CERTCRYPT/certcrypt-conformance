# V033 — Anti-Splicing: Commitment Not Declared Consumed

The verified commitment_id is absent from proof.consumed_commitment_ids,
while the inclusion proof (commitment_id -> subtree_root) and the hybrid
emission binding remain intact. LEAF_BINDING_VALID passes (the path still
verifies against subtree_root); the membership cross-check is the break —
a proof spliced onto a leaf it never declares it consumed.
Expected: INDEPENDENT_INVALID (ANTI_SPLICING_VALID)