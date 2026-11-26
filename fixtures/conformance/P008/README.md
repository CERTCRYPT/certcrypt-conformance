# P008 — Multi-Subject, Truthfully Declared Effective Units

The base certificate anchors THREE subject.binary/1 subjects and the capacity
evidence declares declared_effective_units="3". The verifier recomputes the sum
of per-subject effective units (each non-collection subject contributes 1;
capacity.commitment/1 §13.1) and requires it to equal the declared value. 3 == 3,
so EFFECTIVE_UNITS_BINDING_VALID passes: a truthful multi-subject declaration
verifies.
All checks pass.