# V065 — Issued Verification, Material Does Not Match

Target `issued`, a valid certificate, and material that does not recompute to
the committed subject. The Issued route completed and failed: ISSUED_INVALID,
never a code of the Independent route (verifier-toolkit/1 §9.1, §8.5.2).
Expected: ISSUED_INVALID (ORIGINAL_MATERIAL_COMPARISON_VALID)