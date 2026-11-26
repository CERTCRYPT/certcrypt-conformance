# V041 — Effective-Units Under-Declaration

The base certificate anchors THREE subject.binary/1 subjects, but the capacity
evidence declares declared_effective_units="1" — one unit declared for three
certified subjects. The certificate is cryptographically valid and the emission
binding holds; the break is purely the effective-units equality. The verifier
recomputes Σ per-subject units = 3 (capacity.commitment/1 §13.1) != declared 1
and fails closed. Under the zero-data profile the settlement plane carries
evidence digests, not the subjects, so the offline verifier is the only actor
that can catch this (§13.1.1).
Expected: INDEPENDENT_INVALID (EFFECTIVE_UNITS_BINDING_VALID)