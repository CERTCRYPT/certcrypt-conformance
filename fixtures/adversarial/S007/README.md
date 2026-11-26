# S007 — Altered Node Attestation

P010 with `node_attestation.node_id` replaced after the proof was signed
(`proof_digest` recomputed, signature left as it was). The attestation is part
of the signed view, so the composite signature fails and no node is reported.
Expected: INDEPENDENT_INVALID (PROOF_SIGNATURE_VALID)