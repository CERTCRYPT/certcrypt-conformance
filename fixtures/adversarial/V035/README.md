# V035 — Capacity Evidence Internal Binding Broken (pseudonym splice)

The zero-data capacity evidence recomputes to its commitment_id (so the
hybrid emission binding and inclusion path pass), but the projected
commitment's holder_pseudonym does not match the projected authorization's —
the internal per-commitment binding is broken, as if evidence from a
different holder-projection were spliced into this leaf. This is the
isolated CAPACITY_EVIDENCE_VALID negative for the N>1 binding.
Expected: INDEPENDENT_INVALID (CAPACITY_EVIDENCE_VALID)