# S009 — Proof Signature Components Reordered

The two components are present and each verifies over M', but the ML-DSA-65
component comes first. The order is normative: classical first, PQC second
(composite-signature/1 §7, §8).
Expected: REJECTED (PROOF_SIGNATURE_VALID)