# V055 — anti_replay Bound to Another Settlement Context

P001 whose `anti_replay` is the derivation for a different settlement_ref,
signed by the system domain. It is well formed and authentic, but it does not
equal the derivation from this proof's settlement_ref and subtree_root
(independence.proof/1 §10.9).
Expected: INDEPENDENT_INVALID (NON_REPLAY_VALID)