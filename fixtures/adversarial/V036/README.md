# V036 — Unsupported Proof Version

proof.proof_version is "independence.proof/99", a schema the toolkit does not
implement. The verdict is UNSUPPORTED (not INDEPENDENT_INVALID/REJECTED): the
toolkit cannot assert a verdict under an unknown proof schema — the taxonomy's
UNSUPPORTED case (verifier-toolkit/1 §9).
Expected: UNSUPPORTED (PROOF_VERSION_SUPPORTED)