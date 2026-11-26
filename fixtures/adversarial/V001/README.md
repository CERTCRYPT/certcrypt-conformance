# V001 — Cross-Leaf Proof Splice (hybrid binding STEP 1)

The certificate's anchor.issued_at was altered (and the cert re-signed), so
SHA3(JCS(base_certificate)) no longer equals the
capacity_evidence.projected_commitment.certificate_commitment_digest the
commitment was bound to. The emission binding fails its first leg.
Expected: INDEPENDENT_INVALID (LEAF_BINDING_VALID)