# S006 — Proof of Independence Composite Signature

A valid Independent whose Proof of Independence carries a composite signature
(P-256 + ML-DSA-65, AND) by the system-domain Level-1 capacity key published in
the foundation (system_domain_capacity_key_p256_b64 / _mldsa_b64). The signature
covers the signed view of independence.proof/1 §10.13.1 and is mandatory:
PROOF_SIGNATURE_VALID runs the composite verification over that view. All checks
pass. production_verification is not asserted: the conformance domain is
synthetic.