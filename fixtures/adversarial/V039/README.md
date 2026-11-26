# V039 — Collection Material Does Not Reproduce the Committed Root

One delivered leaf is tampered (record-3 → record-TAMPERED), so the reconstructed
collection.merkle-sha3-256/1 root differs from the committed root. The subject
commitment still matches (same collection object), so the break is the material
comparison, not the emission binding. The comparison belongs to the Issued
route (verifier-toolkit/1 §11.1 step 3), so the code is ISSUED_INVALID; the
independence axis is evaluated separately and is not what failed.
Expected: ISSUED_INVALID (ORIGINAL_MATERIAL_COMPARISON_VALID)