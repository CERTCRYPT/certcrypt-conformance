# P001 — Canonical Valid Aggregated Independence

2-leaf batch, leaf index 0. The target leaf is a sub-tree of 2 accepted
commitments (same issuer_scope + capacity_authorization_ref); the verified
certificate corresponds to commitment index 0. Zero-data capacity evidence
is bound into the proof; the emission binding is hybrid
(SHA3(cert) == certificate_commitment_digest + commitment_id ∈ subtree_root).
Pins subject_scope: the one subject.binary/1 subject is opaque, so the verdict
covers that input as one input and asserts nothing about anything inside it.
All checks pass.