# C016 — Composite Components Out Of Order

The issuer signature lists ML-DSA-65 before the classical component. The
component order is fixed by the profile (composite-signature/1 §8) and is
part of the closed issuer signature layout (CCSP/1 §7.4).
Expected: REJECTED (BASE_CERTIFICATE_STRUCTURE_VALID)