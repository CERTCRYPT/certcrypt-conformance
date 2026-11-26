# V013 — Package-Level Coexistence Without Coherence (hybrid binding STEP 2)

Each artifact is individually well-formed, but the commitment inclusion
proof carries a wrong sibling, so the target commitment_id no longer
recomputes to the proof's subtree_root. The emission binding fails its
second leg (commitment_id ∉ subtree_root).
Expected: INDEPENDENT_INVALID (LEAF_BINDING_VALID)