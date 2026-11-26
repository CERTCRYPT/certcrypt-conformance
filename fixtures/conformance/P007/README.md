# P007 — Collection Subject, Verified Against Delivered Material

A valid Independent whose base certificate carries a subject.collection/1 subject.
The ordered leaf materials (record-1..3) are delivered, so the verifier runs
ORIGINAL_MATERIAL_COMPARISON_VALID: recompute each leaf under subject.binary/1,
rebuild the root under collection.merkle-sha3-256/1, require root == committed root
AND participating-leaf count == declared_cardinality (3), then match the CCCP/1
subject commitment. Drives a collection subject through the full pipeline.
Also exercises EFFECTIVE_UNITS_BINDING_VALID with a collection: declared_effective_units
is "3" and the resolved declared_cardinality is 3, so the exact per-subject sum (3)
equals the declared units (capacity.commitment/1 §13.1.1).
All checks pass.