# V073 — Mixed-Package Substitution

The package carries the proof, evidence, inclusion proof and settlement material
of one certificate, and the base_certificate of another. Both certificates are
valid and name the same system domain and rules version, so the package context
is coherent; the emission binding is what fails (verifier-toolkit/1 §13).
Expected: INDEPENDENT_INVALID (LEAF_BINDING_VALID)