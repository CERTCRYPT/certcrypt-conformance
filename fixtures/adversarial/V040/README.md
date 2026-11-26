# V040 — Collection Leaf Profile Not Admitted

A collection leaf declares subject.unsupported/99, a subject profile the
rules domain does not admit. The admitted set binds every leaf of a
collection, so the certificate is non-conformant: the material plane fails
closed before any leaf is canonicalized, rather than reporting the profile
as merely unsupported.
Expected: REJECTED (ORIGINAL_MATERIAL_COMPARISON_VALID)